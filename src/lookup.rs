use std::net::Ipv4Addr;

// use fastly::handle::client_ip_addr;

use trust_dns_proto::op::ResponseCode;
use trust_dns_proto::rr::{Name, RData, Record, RecordType};

pub struct LookupResult {
    pub rcode: ResponseCode,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additionals: Vec<Record>,
}

pub fn lookup(name: &Name, rr_type: RecordType) -> LookupResult {
    println!("lookup {}:{}", name, rr_type);
    let name = name.to_lowercase();
    let answer = Record::from_rdata(name, 5, RData::A(Ipv4Addr::new(93, 184, 216, 34)));
    let answers = vec![answer];

    LookupResult {
        rcode: ResponseCode::NoError,
        answers: answers,
        authority: Vec::new(),
        additionals: Vec::new(),
    }
}
