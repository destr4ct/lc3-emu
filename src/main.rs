mod lc3;

use std::env;
use lc3::hardware;
use crate::lc3::util::print_crash;



pub fn run_lc3(s: &str) -> hardware::LC3Result<()> {

    let mut vm = hardware::Machine::new();
    vm.setup().load(s)?.execute()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} $PATH", args[0]);
        return;
    }

    if let Err(fault) = run_lc3(&args[1]) {
        print_crash(&fault);
    }
}
