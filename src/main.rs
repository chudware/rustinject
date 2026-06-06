mod gui;
mod inject;
mod injector;
mod process;

use std::env;
use std::path::Path;

use inject::inject_dll_into_process;
use process::get_process_id_by_name;

fn run_cli(dll_path: &str, process_name: &str) {
    let pid = match get_process_id_by_name(process_name) {
        Some(pid) => pid,
        None => {
            eprintln!("Process not found");
            std::process::exit(-1);
        }
    };

    println!("Process pid: {pid}");

    match inject_dll_into_process(pid, Path::new(dll_path)) {
        Ok(()) => println!("OK"),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(-8);
        }
    }
}

fn run_gui() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default().with_inner_size([520.0, 620.0]),
        ..Default::default()
    };

    eframe::run_native(
        "RustInject",
        options,
        Box::new(|cc| Ok(Box::new(gui::InjectorApp::new(cc)))),
    )
}

fn main() -> eframe::Result<()> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();

    if args.is_empty() {
        return run_gui();
    }

    if args.len() >= 2 {
        let dll_path = args.remove(0);
        let process_name = args.remove(0);
        run_cli(&dll_path, &process_name);
        Ok(())
    } else {
        std::process::exit(0);
    }
}
