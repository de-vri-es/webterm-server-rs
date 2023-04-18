use futures::stream::StreamExt;
use futures::sink::SinkExt;
use hyper_tungstenite::tungstenite;
use std::convert::Infallible;
use std::os::unix::process::ExitStatusExt;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod pty;
use pty::PsuedoTerminal;

#[derive(Debug, Clone, clap::Parser)]
struct Options {
	/// Print more messages.
	#[clap(short, long)]
	#[clap(action = clap::ArgAction::Count)]
	verbose: u8,

	/// Print less messages.
	#[clap(short, long)]
	#[clap(action = clap::ArgAction::Count)]
	quiet: u8,

	/// The address to bind to.
	#[clap(short, long)]
	#[clap(default_value = "localhost:8080")]
	listen: String,

	/// The command to execute
	#[clap(default_value = "webterm-login")]
	command: String,

	/// Arguments for the command.
	#[clap(trailing_var_arg = true)]
	args: Vec<String>
}

#[tokio::main]
async fn main() {
	if let Err(()) = do_main(clap::Parser::parse()).await {
		std::process::exit(1);
	}
}

struct Subcommand {
	binary: String,
	args: Vec<String>,
}

async fn do_main(options: Options) -> Result<(), ()> {
	pretty_env_logger::formatted_timed_builder()
		.filter_module(module_path!(), log_level(options.verbose, options.quiet))
		.init();

	let bind_address = options.listen;

	let subcommand = Arc::new(Subcommand {
		binary: options.command,
		args: options.args,
	});

	let listener = tokio::net::TcpListener::bind(&bind_address)
		.await
		.map_err(|e| log::error!("Failed to bind to {bind_address}: {e}"))?;

	let shutdown = async_shutdown::Shutdown::new();

	let server = {
		let shutdown = shutdown.clone();
		async move {
			log::info!("Listener for HTTP connections on http://{bind_address}");
			loop {
				let Some(connection) = shutdown.wrap_cancel(listener.accept()).await else {
					break;
				};
				let (connection, address) = connection
					.map_err(|e| log::error!("Failed to accept connection on {bind_address}: {e}"))?;
				log::info!("Accepted new connection from {address}");

				let subcommand = subcommand.clone();
				let service = hyper::service::service_fn(move |request| handle_request(request, subcommand.clone()));

				let handler = hyper::server::conn::Http::new()
					.http1_keep_alive(true)
					.serve_connection(connection, service)
					.with_upgrades();
				tokio::spawn(handler);
			}

			log::debug!("Stopped accepting connections on {bind_address}");
			Ok::<(), ()>(())
		}
	};
	tokio::spawn(server);

	tokio::spawn({
		let shutdown = shutdown.clone();
		async move {
			for i in 0.. {
				match tokio::signal::ctrl_c().await {
					Ok(()) => log::info!("Received interrupt signal"),
					Err(e) => log::error!("Error waiting for interrupt signal: {e}"),
				}
				if i <= 3 {
					shutdown.shutdown();
				} else {
					log::error!("Received {i} interrupt signals, forcibly exitting");
					std::process::exit(1);
				}
			}
		}
	});

	shutdown.wait_shutdown_triggered().await;
	log::info!("Shutting down server");
	shutdown.wait_shutdown_complete().await;

	Ok(())
}

async fn handle_request(request: hyper::Request<hyper::Body>, subcommand: Arc<Subcommand>) -> Result<hyper::Response<hyper::Body>, Infallible> {
	Ok(match request.uri().path() {
		"/" => serve_static(include_str!("../static/index.html"), "text/html; charset=utf-8"),
		"/xtermjs/xterm.js" => serve_static(include_str!("../static/xtermjs/xterm.js"), "text/javascript"),
		"/xtermjs/xterm.css" => serve_static(include_str!("../static/xtermjs/xterm.css"), "text/css"),
		"/xtermjs/xterm.js.map" => serve_static(include_str!("../static/xtermjs/xterm.js.map"), "application/json"),
		"/xtermjs/xterm-addon-fit.js" => serve_static(include_str!("../static/xtermjs/xterm-addon-fit.js"), "text/javascript"),
		"/xtermjs/xterm-addon-fit.js.map" => serve_static(include_str!("../static/xtermjs/xterm-addon-fit.js.map"), "application/json"),
		"/xtermjs/xterm-addon-search.js" => serve_static(include_str!("../static/xtermjs/xterm-addon-search.js"), "text/javascript"),
		"/xtermjs/xterm-addon-search.js.map" => serve_static(include_str!("../static/xtermjs/xterm-addon-search.js.map"), "application/json"),
		"/xtermjs/xterm-addon-web-links.js" => serve_static(include_str!("../static/xtermjs/xterm-addon-web-links.js"), "text/javascript"),
		"/xtermjs/xterm-addon-web-links.js.map" => serve_static(include_str!("../static/xtermjs/xterm-addon-web-links.js.map"), "application/json"),
		"/terminal" => handle_terminal(request, subcommand.clone()).await,
		_ => not_found(),
	})
}


async fn handle_terminal(request: hyper::Request<hyper::Body>, subcommand: Arc<Subcommand>) -> hyper::Response<hyper::Body> {
	if !hyper_tungstenite::is_upgrade_request(&request) {
		log::error!("Received plain HTTP request for websocket endpoint");
		return bad_request("expected websocket connection");
	}

	let (response, websocket) = match hyper_tungstenite::upgrade(request, Default::default()) {
		Ok(x) => x,
		Err(e) => {
			log::error!("Failed to upgrade HTTP connection to websocket: {e}");
			return internal_server_error("failed to upgrade connection");
		}
	};

	let terminal = match PsuedoTerminal::allocate() {
		Ok(x) => x,
		Err(e) => {
			log::error!("Failed to allocate PTY: {e}");
			return internal_server_error("failed to allocate PTY");
		}
	};
	let mut command = tokio::process::Command::new(&subcommand.binary);
	command.args(&subcommand.args);
	command.env("TERM", "xterm-256color");
	let (tty, child) = match terminal.spawn(command).await {
		Ok(x) => x,
		Err(e) => {
			log::error!("Failed to spawn process {}: {e}", subcommand.binary);
			return internal_server_error("failed to spawn process");
		}
	};
	log::debug!("Spawned child process {} with PID {}", subcommand.binary, child.id().unwrap_or(0));

	tokio::spawn(async move {
		let websocket = match websocket.await {
			Ok(x) => x,
			Err(e) => {
				log::error!("Failed to get websocket stream: {e}");
				return;
			}
		};

		handle_process(websocket, tty, child).await.ok();
	});

	response
}

async fn handle_process(
	mut websocket: hyper_tungstenite::WebSocketStream<hyper::upgrade::Upgraded>,
	mut tty: PsuedoTerminal,
	mut child: tokio::process::Child,
) -> Result<(), ()> {
	let pid = child.id().unwrap_or(0);
	let mut buffer = vec![0u8; 256];
	loop {
		tokio::select! {
			read = tty.read(&mut buffer[1..]) => {
				let read = read.map_err(|e| log::error!("Failed to read from child {pid} PTY: {e}"))?;
				let mut message = std::mem::replace(&mut buffer, vec![0u8; 256]);
				message[0] = b'd';
				message.truncate(read + 1);
				websocket.send(tungstenite::Message::Binary(message))
					.await
					.map_err(|e| log::error!("Failed to send websocket message: {e}"))?;
			},
			message = websocket.next() => {
				let message = message
					.ok_or_else(|| log::info!("Websocket connection for child {pid} closed"))?
					.map_err(|e| log::error!("Failed to read from websocket for child {pid}: {e}"))?;
				match message {
					tungstenite::Message::Binary(data) => {
						let Some(kind) = data.first() else {
							continue;
						};
						let data = &data[1..];
						match kind {
							b'd' => {
								tty.write_all(data.as_ref()).await
									.map_err(|e| log::error!("Failed to write to child {pid} PTY: {e}"))?;
							},
							b'r' => {
								if data.len() != 8 {
									log::error!("Invalid resize message, expected 8 data bytes, got {}", data.len());
									return Err(());
								}
								let width = u32::from_le_bytes(data[0..][..4].try_into().unwrap());
								let height = u32::from_le_bytes(data[4..][..4].try_into().unwrap());
								log::debug!("Resizing terminal for child {pid} to {width}x{height}");
								tty.resize(width, height)
									.map_err(|e| log::error!("Failed to resize terminal for child {pid} to {width}x{height}: {e}"))
									.ok();
							},
							_ => {
								log::error!("Received unknown websocket message for child {pid} with type {kind}");
								return Err(());
							},
						}
					},
					tungstenite::Message::Ping(_) => (),
					tungstenite::Message::Pong(_) => (),
					_ => {
						log::error!("Received unsupported websocket message for child {pid}: {message:?}");
					}
				};
			},
			status = child.wait() => {
				let status = status
					.map_err(|e| log::error!("Failed to wait for child process with PID {pid}: {e}"))?;
				if status.success() {
					log::debug!("Child process {pid} exitted cleanly");
				} else if let Some(signal) = status.signal() {
					log::debug!("Child process {pid} killed by signal {signal}");
				} else if let Some(code) = status.code() {
					log::debug!("Child process {pid} exitted with code {code}");
				} else {
					log::debug!("Child process {pid} terminated for unknown reason");
				}
				break;
			},
		}
	}

	if let Err(e) = child.kill().await {
		log::error!("Failed to kill child {pid}: {e}");
	}
	Ok(())
}

fn serve_static(data: &'static str, content_type: &'static str) -> hyper::Response<hyper::Body> {
	let mut response = hyper::Response::new(hyper::Body::from(data));
	response.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static(content_type));
	response.headers_mut().insert(hyper::header::CACHE_CONTROL, hyper::header::HeaderValue::from_static("max-age=604800"));
	response
}

fn not_found() -> hyper::Response<hyper::Body> {
	let mut response = serve_static("404 Not Found", "text/plain; charset=utf-8");
	*response.status_mut() = hyper::StatusCode::NOT_FOUND;
	response
}

fn bad_request(message: &'static str) -> hyper::Response<hyper::Body> {
	let mut response = serve_static(message, "text/plain; charset=utf-8");
	*response.status_mut() = hyper::StatusCode::BAD_REQUEST;
	response
}

fn internal_server_error(message: &'static str) -> hyper::Response<hyper::Body> {
	let mut response = serve_static(message, "text/plain; charset=utf-8");
	*response.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
	response
}

fn log_level(verbose: u8, quiet: u8) -> log::LevelFilter {
	match verbose as i8 - quiet as i8 {
		i8::MIN..=-2 => log::LevelFilter::Error,
		-1 => log::LevelFilter::Warn,
		0 => log::LevelFilter::Info,
		1 => log::LevelFilter::Debug,
		2..=i8::MAX => log::LevelFilter::Trace,
	}
}
