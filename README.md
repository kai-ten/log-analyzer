# CyberVISOR Log Analysis

## Inspiration:

- https://github.com/SigmaHQ/sigma
- https://github.com/confluentinc/cyber
- https://www.csoonline.com/article/3663691/sigma-rules-explained-when-and-how-to-use-them-to-log-events.html


Left off at trying to figure out the best way to store an Option for each field that is not required. Must be able to 
parse whether a value exists or not at run time without erroring out


Left off at trying to implement Generic Option to return either a SigmaRule or None
- If it returns Sigma rule, add to detections. 
- Else bubble up to get next rule in files if there is one

For the rules, check if the yaml is None or Some
- If None, return all the way up 

Make a controller file that coordinates the flow of adding a sigma rule / yml file
1. addRulesController, returns result<Ok()>
   1. For each file in rules directory, return<Ok(SigmaRule), Err(Error)>
      1. open and read yml file
      2. Pass yaml Value, return yml_mapping Option<&Value>
      3. pass yml_mapping and build the sigma rule based on sets of rules, Result<Ok(), Error()>
         1. if field is_none, then return Result<Ok(), Error()>
         2. 
      4. If rule is good, add to active detections

Must propagate all error handling in order to safely quit processing a rule if it is invalid and continue operating.