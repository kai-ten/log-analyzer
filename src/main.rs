mod parser;
use parser::sigma_rule::SigmaRule;

fn main() {
    println!("HELLO");
    let read_result = SigmaRule::read_yml();
    // println!("result = {:?}", read_result);
}


