#!/usr/bin/env python3
# coding=utf-8
import duckdb
import logging
# import glob

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, filename="run.log", format=LOG_FORMAT)

DB_FILE_NAME = "dnslog.db"

create_sql = """CREATE TABLE IF NOT EXISTS dnsevent (
    EventTime DATETIME,
    SourceIP VARCHAR,
    SourcePort USMALLINT,
    DestinationIP VARCHAR,
    DestinationPort USMALLINT,
    TranscationID USMALLINT,
    View VARCHAR,
    Domain VARCHAR,
    QueryClass VARCHAR,
    QueryType VARCHAR,
    Rcode VARCHAR,
    Response BOOLEAN,
    Authoritative BOOLEAN,
    Truncated BOOLEAN,
    RecursionDesired BOOLEAN,
    RecursionAvailable BOOLEAN,
    Zero BOOLEAN,
    AuthenticatedData BOOLEAN,
    CheckingDisabled BOOLEAN,
    DelayMicrosecond BIGINT,
    Answer STRUCT(
        Domain VARCHAR,
        TTL UINTEGER,
        Rclass VARCHAR,
        Rtype VARCHAR,
        Rdata VARCHAR
        )[],
    Authority STRUCT(
        Domain VARCHAR,
        TTL UINTEGER,
        Rclass VARCHAR,
        Rtype VARCHAR,
        Rdata VARCHAR
        )[],
    Additional STRUCT(
        Domain VARCHAR,
        TTL UINTEGER,
        Rclass VARCHAR,
        Rtype VARCHAR,
        Rdata VARCHAR
        )[],
    Edns VARCHAR,
    EdnsClientSubnet VARCHAR,
    EdnsClientSubnetInfo STRUCT(
        IP VARCHAR,
        Country VARCHAR,
        Province VARCHAR,
        City VARCHAR,
        County VARCHAR,
        Isp VARCHAR,
        DC VARCHAR,
        App VARCHAR,
        Custom VARCHAR
    ),
    SourceIpInfo STRUCT(
        IP VARCHAR,
        Country VARCHAR,
        Province VARCHAR,
        City VARCHAR,
        County VARCHAR,
        Isp VARCHAR,
        DC VARCHAR,
        App VARCHAR,
        Custom VARCHAR
    ),
    AnswerIP VARCHAR,
    AnswerIpInfo STRUCT(
        IP VARCHAR,
        Country VARCHAR,
        Province VARCHAR,
        City VARCHAR,
        County VARCHAR,
        Isp VARCHAR,
        DC VARCHAR,
        App VARCHAR,
        Custom VARCHAR
    ),
    SecondLevelDomain VARCHAR,
    ByteLength UINTEGER,
    QueryByteLength UINTEGER,
    SubdomainByteLength UINTEGER,
    LabelCount UINTEGER,
    SubdomainLabelCount UINTEGER,
    SubdomainEntropy DOUBLE,
    SubdomainLabelEncoded BOOLEAN,
    TrafficDirection VARCHAR
)"""


def initDB(conn: duckdb.DuckDBPyConnection):
    conn.sql(create_sql)
    conn.install_extension("json")
    conn.load_extension("json")


def copyJsonlogFile(conn: duckdb.DuckDBPyConnection, jsonlog_filename: str):
    if jsonlog_filename == "":
        logging.error("jsonlog filename is empty, ignore it")
        return
    logging.info("begin copy {} to database".format(jsonlog_filename))
    conn.sql("COPY dnsevent FROM '{}'".format(jsonlog_filename))
    logging.info("end copy {} to database".format(jsonlog_filename))


# def listJsonlogFiles(logdir: str, logfile_prefix) -> list:
# files = glob.glob(logfile_prefix + "*")
