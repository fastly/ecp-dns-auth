use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Deserialize;
use tracing::debug;

use trust_dns_proto::op::{Header, Message, MessageType, Query, ResponseCode};
use trust_dns_proto::rr::{rdata, Name, RData, Record, RecordType};

use crate::lookup::LookupResult;

pub fn dns_error(request: Message, rcode: ResponseCode) -> Message {
    Message::error_msg(request.id(), request.op_code(), rcode)
}

pub fn dns_response(req_header: &Header, query: &Query, result: LookupResult) -> Message {
    let mut header = Header::response_from_request(req_header);
    header.set_message_type(MessageType::Response);
    header.set_authoritative(true);

    let mut response = Message::new();
    response.set_header(header);
    response.set_response_code(result.rcode);
    response.add_query(query.clone());
    response.insert_answers(result.answers);
    response.insert_name_servers(result.authority);
    response.insert_additionals(result.additionals);
    debug!("response: {:?}", response);
    response
}

#[derive(Deserialize, Debug)]
pub struct JsonRRMap {
    A: Option<JsonA>,
    AAAA: Option<JsonAAAA>,
    MX: Option<JsonMX>,
    NS: Option<JsonNS>,
    SOA: Option<JsonSOA>,
}

impl JsonRRMap {
    pub fn get(&self, name: &Name, rr_type: RecordType) -> Vec<Record> {
        match (rr_type, self) {
            (RecordType::A, JsonRRMap { A: Some(a), .. }) => a.to_rrs(name),
            (
                RecordType::AAAA,
                JsonRRMap {
                    AAAA: Some(aaaa), ..
                },
            ) => aaaa.to_rrs(name),
            (RecordType::MX, JsonRRMap { MX: Some(mx), .. }) => mx.to_rrs(name),
            (RecordType::NS, JsonRRMap { NS: Some(ns), .. }) => ns.to_rrs(name),
            (RecordType::SOA, JsonRRMap { SOA: Some(soa), .. }) => soa.to_rrs(name),
            _ => Vec::new(), // couldn't find rrs of the requested type
        }
    }
}

#[derive(Deserialize, Debug)]
struct JsonA {
    ttl: u32,
    values: Vec<Ipv4Addr>,
}

impl JsonA {
    fn to_rrs(&self, name: &Name) -> Vec<Record> {
        self.values
            .iter()
            .map(|v| Record::from_rdata(name.clone(), self.ttl, RData::A(*v)))
            .collect()
    }
}

#[derive(Deserialize, Debug)]
struct JsonAAAA {
    ttl: u32,
    values: Vec<Ipv6Addr>,
}

impl JsonAAAA {
    fn to_rrs(&self, name: &Name) -> Vec<Record> {
        self.values
            .iter()
            .map(|v| Record::from_rdata(name.clone(), self.ttl, RData::AAAA(*v)))
            .collect()
    }
}

#[derive(Deserialize, Debug)]
struct JsonMXValue {
    exchange: Name,
    preference: u16,
}

#[derive(Deserialize, Debug)]
struct JsonMX {
    ttl: u32,
    values: Vec<JsonMXValue>,
}

impl JsonMX {
    fn to_rrs(&self, name: &Name) -> Vec<Record> {
        self.values
            .iter()
            .map(|v| {
                Record::from_rdata(
                    name.clone(),
                    self.ttl,
                    RData::MX(rdata::MX::new(v.preference, v.exchange.clone())),
                )
            })
            .collect()
    }
}

#[derive(Deserialize, Debug)]
struct JsonNS {
    ttl: u32,
    values: Vec<Name>,
}

impl JsonNS {
    fn to_rrs(&self, name: &Name) -> Vec<Record> {
        self.values
            .iter()
            .map(|v| Record::from_rdata(name.clone(), self.ttl, RData::NS(v.clone())))
            .collect()
    }
}

#[derive(Deserialize, Debug)]
struct JsonSOAValue {
    mname: Name,
    rname: Name,
    serial: u32,
    refresh: i32,
    retry: i32,
    expire: i32,
    minimum: u32,
}

#[derive(Deserialize, Debug)]
struct JsonSOA {
    ttl: u32,
    value: JsonSOAValue,
}

impl JsonSOA {
    fn to_rrs(&self, name: &Name) -> Vec<Record> {
        vec![Record::from_rdata(
            name.clone(),
            self.ttl,
            RData::SOA(rdata::SOA::new(
                self.value.mname.clone(),
                self.value.rname.clone(),
                self.value.serial,
                self.value.refresh,
                self.value.retry,
                self.value.expire,
                self.value.minimum,
            )),
        )]
    }
}
