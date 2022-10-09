use std::net::{IpAddr, Ipv4Addr};
use std::{io, str::FromStr};

use fastly::handle::client_ip_addr;
use fastly::http::{header, Method, StatusCode};
use fastly::{Error, Request, Response};
use serde_json::json;

use trust_dns_proto::error::ProtoError;
use trust_dns_proto::op::{Header, Message, ResponseCode};
use trust_dns_proto::rr::{Name, RData, Record};
use trust_dns_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncoder};
use trust_dns_server::authority::{MessageRequest, MessageResponseBuilder};

fn debug_json() -> String {
    json!({
        "version": std::env::var("FASTLY_SERVICE_VERSION").unwrap_or_else(|_| String::new()),
        "sid": std::env::var("FASTLY_SERVICE_ID").unwrap_or_else(|_| String::new()),
        "trace_id": std::env::var("FASTLY_TRACE_ID").unwrap_or_else(|_| String::new()),
    })
    .to_string()
}

fn query_from_qstring(req: Request) -> Option<Vec<u8>> {
    let question_str = req.get_query_parameter("dns");
    let query = match question_str
        .and_then(|question_str| base64::decode_config(question_str, base64::URL_SAFE_NO_PAD).ok())
    {
        Some(query) => query,
        _ => return None,
    };
    Some(query)
}

fn handle_doh_get(req: Request) -> Result<Response, Error> {
    let query = match query_from_qstring(req) {
        Some(query) => query,
        _ => {
            return Ok(Response::from_status(StatusCode::BAD_REQUEST)
                .with_body_text_plain("Missing or invalid query string\n"))
        }
    };
    handle_doh_request(query)
}

fn handle_doh_post(req: Request) -> Result<Response, Error> {
    handle_doh_request(req.into_body_bytes())
}

fn handle_doh_request(raw_msg: Vec<u8>) -> Result<Response, Error> {
    match handle_request(raw_msg) {
        Ok(response) => Ok(Response::from_status(StatusCode::OK)
            .with_body_octet_stream(&response)
            .with_header(header::CONTENT_TYPE, "application/dns-message")),
        _ => Ok(Response::from_status(StatusCode::BAD_REQUEST)
            .with_body_text_plain("Unable to parse DNS query\n")),
    }
}

fn handle_request(raw_msg: Vec<u8>) -> Result<Vec<u8>, ProtoError> {
    println!("raw_msg: {:X?}", raw_msg);

    let mut decoder = BinDecoder::new(&raw_msg);
    let msg_req = MessageRequest::read(&mut decoder)?;
    println!("MessageRequest {:?}", msg_req);

    // at this point we have a well-formed DNS query so even in the
    // case of other errors we will be returning a DNS response.
    let header = msg_req.header();
    let query = msg_req.query();
    println!("header: {:?}", header);
    println!("query: {:?}", query);

    // TODO actually look up the query
    let answer = match client_ip_addr().unwrap() {
        IpAddr::V4(ipv4) => Record::from_rdata(
            Name::from_str("www.example.com").unwrap(),
            5,
            RData::A(ipv4),
        ),
        IpAddr::V6(ipv6) => Record::from_rdata(
            Name::from_str("www.example.com").unwrap(),
            5,
            RData::AAAA(ipv6),
        ),
    };

    let answer2 = Record::from_rdata(
        Name::from_str("www.example.com").unwrap(),
        5,
        RData::A(Ipv4Addr::new(1, 2, 3, 4)),
    );

    let answer3 = Record::from_rdata(
        Name::from_str("www.example.com").unwrap(),
        5,
        RData::A(Ipv4Addr::new(5, 6, 7, 8)),
    );

    let answers = [&answer, &answer2, &answer3];
    let ns = None.into_iter();
    let soa = None.into_iter();
    let additionals = None.into_iter();

    // build response
    let mut response_header = Header::response_from_request(header);
    response_header.set_authoritative(true);
    let msg_resp = MessageResponseBuilder::from_message_request(&msg_req).build(
        response_header,
        answers,
        ns,
        soa,
        additionals,
    );
    println!("msg_resp: {:?}", msg_resp);

    let mut buffer = Vec::with_capacity(512);
    let encode_result = {
        let mut encoder = BinEncoder::new(&mut buffer);
        msg_resp.destructive_emit(&mut encoder)
    };

    encode_result.map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("error encoding message: {}", e),
        )
    })?;

    return Ok(buffer);
}

fn handle_request_orig(raw_msg: Vec<u8>) -> Result<Vec<u8>, ProtoError> {
    println!("raw_msg: {:X?}", raw_msg);

    let mut request = Message::from_vec(&raw_msg)?;
    println!("request: {:?}", request);

    // at this point we have a well-formed DNS query so even in the
    // case of other errors we will be returning a DNS response.

    let queries = request.take_queries();
    let query = match queries.first() {
        Some(query) if queries.len() == 1 => query,
        _ => {
            return Message::error_msg(request.id(), request.op_code(), ResponseCode::FormErr)
                .to_vec()
        }
    };

    println!("query: {:?}", query);

    let mut response_header = Header::response_from_request(request.header());
    response_header.set_authoritative(true);
    // response_header.set_answer_count(1);
    let mut response = Message::new();
    response.set_header(response_header);

    match client_ip_addr().unwrap() {
        IpAddr::V4(ipv4) => {
            response.add_answer(Record::from_rdata(
                Name::from_str("www.example.com").unwrap(),
                5,
                RData::A(ipv4),
            ));
        }
        IpAddr::V6(ipv6) => {
            response.add_answer(Record::from_rdata(
                Name::from_str("www.example.com").unwrap(),
                5,
                RData::AAAA(ipv6),
            ));
        }
    }

    let answer2 = Record::from_rdata(
        Name::from_str("www.example.com").unwrap(),
        5,
        RData::A(Ipv4Addr::new(1, 2, 3, 4)),
    );

    let answer3 = Record::from_rdata(
        Name::from_str("www.example.com").unwrap(),
        5,
        RData::A(Ipv4Addr::new(5, 6, 7, 8)),
    );
    let answer4 = Record::from_rdata(
        Name::from_str("www.example.com").unwrap(),
        5,
        RData::A(Ipv4Addr::new(5, 6, 7, 8)),
    );

    response.add_answer(answer2);
    response.add_answer(answer3);
    response.add_answer(answer4);

    response.add_queries(queries);

    println!("response: {:?}", response);

    return response.to_vec();

    /*
        return Ok(vec![
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77,
            0x77, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00,
            0x1C, 0x00, 0x01, 0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x7D, 0x00, 0x10,
            0x20, 0x01, 0x0D, 0xB8, 0xAB, 0xCD, 0x00, 0x12, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00,
            0x04,
        ]);
    */
}

#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {
    match (
        req.get_method(),
        req.get_path(),
        req.get_header_str(header::CONTENT_TYPE),
    ) {
        (&Method::GET, "/dns-query", Some("application/dns-message")) => handle_doh_get(req),
        (&Method::POST, "/dns-query", Some("application/dns-message")) => handle_doh_post(req),

        (&Method::GET, "/resolve", ..) => {
            return Ok(Response::from_status(StatusCode::OK).with_body_text_plain("TODO json\n"))
        }

        (&Method::GET, "/query", ..) => {
            return Ok(
                Response::from_status(StatusCode::OK).with_body_text_plain("TODO html form\n")
            )
        }

        (&Method::GET, "/debug", ..) => {
            return Ok(Response::from_status(StatusCode::OK).with_body_text_plain(&debug_json()))
        }

        _ => {
            // Catch all other requests and return a 404.
            return Ok(Response::from_status(StatusCode::NOT_FOUND)
                .with_header("x-dns-auth-debug", debug_json())
                .with_body_text_plain("Not Found\n"));
        }
    }
}
