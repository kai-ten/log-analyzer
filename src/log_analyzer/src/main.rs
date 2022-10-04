extern crate core;
use sigma_rule_parser;

mod detection;
// mod field_mappings;
// mod server;

use crate::detection::process_detection;
use anyhow::Error;
use log::info;
use log4rs;
use sigma_rule_parser::sigma_file::sigma_rule::process_sigma_rules;

// Main should...
// N/A    0. Read a config file in case path is different than defaults (for rules, field mappings, kafka/http/etc props)
// DONE - 1. Add all rules
// N/A    2. Add field mappings
// INPROG 3. Create detections from conditions
// N/A    4. Begin loop of processing requests (start with simple rules, not aggregate until able to back with Kafka / Redis / Elastic)
// N/A    5. Within loop, begin async concurrent processing of sigma rules in memory

// #[actix_web::main]
fn main() -> Result<(), Error> {
    log4rs::init_file("config/log4rs.yaml", Default::default()).unwrap();

    let sigma_rules =
        process_sigma_rules("config/rules/proc_access_win_mimikatz_through_winrm.yml".to_string())?; // this should be a path

    println!("{:?}", sigma_rules);
    let nice = process_detection(sigma_rules);
    Ok(())
    //

    // let f_m = field_mappings::parse_field_mappings();
    //
    // server::create_server().await
}
