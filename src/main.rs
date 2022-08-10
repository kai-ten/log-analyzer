mod parser;

use std::error::Error;
use parser::sigma_rule::SigmaRule;

fn main() {
    println!("HELLO");
    match SigmaRule::read_yml() {
        Ok(_) => println!("ok"),
        Err(_) => println!("err = ")
    }
    // println!("result = {:?}", read_result);
}


