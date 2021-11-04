##########################################################
#                                                        #
# Autor: Rafael Silva                                    #
# Linkedin: https://www.linkedin.com/in/rafaelsouzasilva #
# Auditor Sênior | Cyber Security                        #
# Data: 31/10/2021                                       #
#                                                        #
#                                                        #
##########################################################

create role r_auditoria;
grant create session to r_auditoria;
grant create table to r_auditoria;
grant create procedure to r_auditoria;
grant create view to r_auditoria;
grant select on v_$system_parameter to r_auditoria;
grant select on DBA_PROFILES to r_auditoria;
grant select on DBA_USERS to r_auditoria;

grant select on dba_tab_privs to r_auditoria;
grant select on DBA_SYS_PRIVS to r_auditoria;
grant select on ALL_TAB_PRIVS to r_auditoria;

create user auditoria identified by auditoria;
grant r_auditoria to auditoria;

create tablespace tbs_auditoria
datafile '/u01/app/oracle/oradata/tablespaces/tbs_auditoria.dbf'
size 100M autoextend on next 10M maxsize 200M
logging
extent management local
segment space management auto;

alter user auditoria default tablespace tbs_auditoria;
alter user auditoria quota unlimited on tbs_auditoria;
