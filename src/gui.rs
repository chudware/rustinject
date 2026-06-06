use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use eframe::egui;

use crate::inject::inject_dll_into_process;
use crate::process::{enable_debug_privilege, list_processes, ProcessInfo};

enum InjectResult {
    Ok,
    Err(String),
}

pub struct InjectorApp {
    dll_path: Option<PathBuf>,
    processes: Vec<ProcessInfo>,
    process_search: String,
    selected_pid: Option<u32>,
    status: String,
    injecting: bool,
    result_rx: Option<Receiver<InjectResult>>,
}

impl InjectorApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        enable_debug_privilege();
        Self {
            dll_path: None,
            processes: list_processes(),
            process_search: String::new(),
            selected_pid: None,
            status: String::new(),
            injecting: false,
            result_rx: None,
        }
    }

    fn filtered_processes(&self) -> Vec<ProcessInfo> {
        let query = self.process_search.trim().to_ascii_lowercase();
        self.processes
            .iter()
            .filter(|p| {
                query.is_empty()
                    || p.name.to_ascii_lowercase().contains(&query)
                    || p.pid.to_string().contains(&query)
            })
            .cloned()
            .collect()
    }

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect()
        });

        for path in dropped {
            if path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("dll")) {
                self.dll_path = Some(path);
                self.status.clear();
                break;
            } else {
                self.status = "Dropped file must be a .dll".to_string();
            }
        }
    }

    fn start_injection(&mut self, ctx: &egui::Context) {
        let (pid, dll_path) = match (self.selected_pid, self.dll_path.clone()) {
            (Some(pid), Some(path)) => (pid, path),
            _ => return,
        };

        self.injecting = true;
        self.status = format!("Injecting into PID {pid}...");

        let (tx, rx): (Sender<InjectResult>, Receiver<InjectResult>) = mpsc::channel();
        self.result_rx = Some(rx);
        let ctx = ctx.clone();

        thread::spawn(move || {
            let result = match inject_dll_into_process(pid, &dll_path) {
                Ok(()) => InjectResult::Ok,
                Err(err) => InjectResult::Err(err),
            };
            let _ = tx.send(result);
            ctx.request_repaint();
        });
    }

    fn poll_injection(&mut self) {
        let Some(rx) = &self.result_rx else {
            return;
        };

        match rx.try_recv() {
            Ok(InjectResult::Ok) => {
                self.status = "Injection successful".to_string();
                self.injecting = false;
                self.result_rx = None;
            }
            Ok(InjectResult::Err(err)) => {
                self.status = err;
                self.injecting = false;
                self.result_rx = None;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.status = "Injection thread disconnected unexpectedly".to_string();
                self.injecting = false;
                self.result_rx = None;
            }
        }
    }
}

impl eframe::App for InjectorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_dropped_files(ctx);
        self.poll_injection();

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("RustInject");
            ui.add_space(8.0);

            ui.label("DLL");
            let drop_frame = egui::Frame::default()
                .fill(ui.visuals().widgets.inactive.bg_fill)
                .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
                .inner_margin(egui::Margin::symmetric(12, 20))
                .corner_radius(6.0);

            drop_frame.show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    if let Some(path) = &self.dll_path {
                        ui.label(egui::RichText::new(path.display().to_string()).strong());
                        ui.label("Drag another .dll here to replace");
                    } else {
                        ui.label("Drag and drop a .dll here");
                    }
                });
            });

            ui.add_space(12.0);

            ui.horizontal(|ui| {
                ui.label("Process");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(!self.injecting, egui::Button::new("Refresh"))
                        .clicked()
                    {
                        self.processes = list_processes();
                        if let Some(pid) = self.selected_pid {
                            if !self.processes.iter().any(|p| p.pid == pid) {
                                self.selected_pid = None;
                            }
                        }
                    }
                });
            });

            ui.add(
                egui::TextEdit::singleline(&mut self.process_search)
                    .hint_text("Search by process name or PID...")
                    .desired_width(f32::INFINITY),
            );

            ui.add_space(4.0);

            let filtered = self.filtered_processes();
            let row_height = ui.text_style_height(&egui::TextStyle::Body) + 8.0;
            let list_height = 280.0;

            egui::ScrollArea::vertical()
                .max_height(list_height)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if filtered.is_empty() {
                        ui.label("No matching processes");
                        return;
                    }

                    for process in filtered {
                        let selected = self.selected_pid == Some(process.pid);
                        let label = format!("{}  (PID {})", process.name, process.pid);

                        let response = ui.add_sized(
                            [ui.available_width(), row_height],
                            egui::SelectableLabel::new(selected, label),
                        );

                        if response.clicked() {
                            self.selected_pid = Some(process.pid);
                            self.status.clear();
                        }
                    }
                });

            ui.add_space(12.0);

            let can_inject = self.dll_path.is_some()
                && self.selected_pid.is_some()
                && !self.injecting;

            if ui
                .add_enabled(can_inject, egui::Button::new("Inject"))
                .clicked()
            {
                self.start_injection(ctx);
            }

            if !self.status.is_empty() {
                ui.add_space(8.0);
                let color = if self.status.starts_with("Injection successful") {
                    egui::Color32::from_rgb(80, 180, 100)
                } else if self.injecting {
                    ui.visuals().weak_text_color()
                } else {
                    egui::Color32::from_rgb(220, 90, 90)
                };
                ui.colored_label(color, &self.status);
            }
        });
    }
}
