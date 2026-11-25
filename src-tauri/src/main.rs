#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod backend;
mod components;
mod config;
mod daemon;
mod util;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // тот же бинарник, запущенный с повышенными правами, работает как ядро туннеля без окна
    if args.iter().any(|a| a == "--core") {
        std::process::exit(daemon::core_main(&args));
    }
    app::run();
}
