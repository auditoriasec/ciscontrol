##########################################################
#                                                        #
# Autor: Rafael Silva                                    #
# Linkedin: https://www.linkedin.com/in/rafaelsouzasilva #
# Auditor Sênior | Cyber Security                        #
# Data: 04/11/2021                                       #
#                                                        #
##########################################################

/* CRIAÇÃO DE ROLE" */

create role r_auditoria;

/* GRANT PARA CONSULTA */

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

/* Criação de usuário */

create user auditoria identified by auditoria;

/*Concessão de ROLE */

grant r_auditoria to auditoria;

/* Criação de tablespace */

create tablespace tbs_auditoria
datafile '/u01/app/oracle/oradata/tablespaces/tbs_auditoria.dbf'
size 100M autoextend on next 10M maxsize 200M
logging
extent management local
segment space management auto;

/* Definição de tablespace para usuário */

alter user auditoria default tablespace tbs_auditoria;
alter user auditoria quota unlimited on tbs_auditoria;
