## extended explanation of policy values

- `pattern_key` describes that substring match on the json key field, which occurs only once in the whole record
- `value_start_idx_after_key` describes the start index of the value field. To identify the start index after they key, you take the last index of the substring pattern match and start counting from there.
- `value_length` describes the length of the value field and indicates which part of the value a prover should compare against the constaint. 
- `threshold_value` indicates a value which the value, located in the plaintext, is compared against. 
- `value_constraint` indicates the comparison operator, e.g. greater than (GT), less than (LT), equal (EQ), etc.

### to be added
- `value_type` indicates if the plaintext value of interest is of type float, integer, string, etc.
