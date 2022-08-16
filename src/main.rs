pub mod sigma_rules;
pub mod yml;

use anyhow::Error;
use sigma_rules::SigmaRule;

// Main should
// 1. Add all rules
// 2. Add field mappings
// 3. Begin loop of processing requests (start with simple rules, not aggregate until able to back with Kafka / Redis / Elastic)
// 4. Within loop, begin async concurrent processing of sigma rules in memory

fn main() -> Result<(), Error> {
    // SigmaRule::add_rules("config/rules".to_string()).unwrap();

    SigmaRule::output_format();

    Ok(())
    // match SigmaRule::read_yml() {
    //     Ok(_) => println!("ok"),
    //     Err(_) => println!("err = ") 
    // }
    // println!("result = {:?}", read_result);
}


