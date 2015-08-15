Objective: To secure sensitive data from people who have direct access to the DB, unless authorized.

Solution (using VPD): VPD Using column masking technique to hide valuable data from un-authorized user’s based on the policy we define(no encryption/decryption overhead here).

Steps to implement: 
•	Use dbms_rls package to create the policy.
•	A function which implements the policy
•	(if required we can)Assign “exempt access policy” to users to be excluded from the policy. These users can see all data with no masking.

Example: (I had created EMP table with SSN as sensitive column.)

--policy
BEGIN
  DBMS_RLS.ADD_POLICY(object_schema=>'TESTDEV', 
  object_name=>'EMP',
  policy_name=>'SSN_POLICY',
  function_schema=>'TESTDEV',
  policy_function=>'hide_ssn',
  sec_relevant_cols=>'EMP_SSN',
  sec_relevant_cols_opt=>dbms_rls.ALL_ROWS);
END;

--  here TESTDEV: schema name, EMP: table name (object),  SSN_POLICY: policy name(can be anything), TESTDEV(function_schema): schema in which function is defined, hide_ssn(policy_function):  function which is implementing the policy,
--  EMP_SSN(sec_relevant_cols): sensitive column of EMP table, we need to mask.

--function (implementing the policy)
create or replace function hide_ssn
(p_owner in varchar2, p_name in varchar2 )
return varchar2
as
begin
      if sys_context( 'userenv', 'session_user' ) = 'USER1' and sys_context( 'userenv', 'IP_ADDRESS' ) = '10.6.134.177' and SYS_CONTEXT('USERENV', 'HOST') = 'SOME_HOST_NAME'
      then
      return '1=1';
      else
      return '1=0';
      end if;
end;

--  this function will return true only if the session_user is from ‘USER1’, request is coming from IP Address 10.6.134.177 and its host name is SOME_HOST_NAME(there are many condition’s which we can apply, but this was applicable in our case)
-- based on whether this function returns true/false, the sensitive columns will be shown or masked respectively.

*** This policy and function are executed only when the concerned table comes in the picture, and is evaluated only once for each request(not for every selected row), hence no performance overhead. ***
