#[macro_export]
macro_rules! warning {
    ($($arg:tt)*) => {{
        use crossterm::style::Stylize;
        println!("\n{}: {}", "Warning".dark_yellow(), format!($($arg)*));
    }};
}

#[macro_export]
macro_rules! log {
    () => {{
        println!();
    }};
    ($($arg:tt)*) => {{
        println!($($arg)*);
    }};
}
