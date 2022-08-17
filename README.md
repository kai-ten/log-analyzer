# CyberVISOR Log Analysis

## Run the app

- cargo run
- RUST_BACKTRACE=1 cargo test -- --show-output

## Inspiration:

- https://github.com/SigmaHQ/sigma
- https://github.com/confluentinc/cyber
- https://www.csoonline.com/article/3663691/sigma-rules-explained-when-and-how-to-use-them-to-log-events.html


RETHINK THE BELOW STUFF
Make a controller file that coordinates the flow of adding a sigma rule / yml file
1. addRulesController, returns result<Ok()>
   1. For each file in rules directory, return<Ok(SigmaRule), Err(Error)>
      1. Open and deserialize yml file
      3. pass yml_mapping and build the sigma rule based on sets of rules, Result<Ok(), Error()>
         1. if field is_none, then return Result<Ok(), Error()>
         2. 
      4. If rule is good, add to active detections

Must propagate all error handling in order to safely quit processing a rule if it is invalid and continue operating.