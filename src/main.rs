use std::str::FromStr;

use fastly::error::anyhow;
use fastly::http::{header, Method, StatusCode};
use fastly::{mime, Error, Request, Response};
use handlebars::Handlebars;
use serde::Serialize;
use serde_json::{json, to_string_pretty, Value as JsonValue};
use tracing::{debug, info, instrument, Level};
use tracing_subscriber::fmt::format;

use trust_dns_proto::error::ProtoError;
use trust_dns_proto::op::{Header, Message, MessageType, OpCode, Query, ResponseCode};
use trust_dns_proto::rr::{Name, Record, RecordType};

mod lookup;
use crate::lookup::lookup;

mod dns;
use crate::dns::{dns_error, dns_response};

const MIME_APPLICATION_DNS: &str = "application/dns-message";

#[instrument]
fn handle_debug() -> Result<Response, Error> {
    let debug_json = json!({
        "version": std::env::var("FASTLY_SERVICE_VERSION").unwrap_or_else(|_| String::new()),
        "sid": std::env::var("FASTLY_SERVICE_ID").unwrap_or_else(|_| String::new()),
        "trace_id": std::env::var("FASTLY_TRACE_ID").unwrap_or_else(|_| String::new()),
    })
    .to_string();

    Ok(Response::from_status(StatusCode::OK).with_body_text_plain(&debug_json))
}

#[instrument(skip_all)]
fn handle_doh_get(req: Request) -> Result<Response, Error> {
    match req
        .get_query_parameter("dns")
        .and_then(|dns| base64::decode_config(dns, base64::URL_SAFE_NO_PAD).ok())
    {
        Some(query) => return handle_doh_request(query),
        _ => {
            return Ok(Response::from_status(StatusCode::BAD_REQUEST)
                .with_body_text_plain("Missing or invalid 'dns' parameter\n"))
        }
    };
}

#[instrument(skip_all)]
fn handle_doh_post(req: Request) -> Result<Response, Error> {
    handle_doh_request(req.into_body_bytes())
}

fn handle_doh_request(raw_msg: Vec<u8>) -> Result<Response, Error> {
    match handle_dns_request(raw_msg) {
        Ok(response) => Ok(Response::from_status(StatusCode::OK)
            .with_body_octet_stream(&response)
            .with_header(header::CONTENT_TYPE, MIME_APPLICATION_DNS)),
        Err(error) => Ok(Response::from_status(StatusCode::BAD_REQUEST)
            .with_body_text_plain(&format!("Invalid DNS query: {}\n", error))),
    }
}

fn handle_dns_request(msg: Vec<u8>) -> Result<Vec<u8>, ProtoError> {
    let request = Message::from_vec(&msg)?;
    debug!("request: {:?}", request);

    // at this point we have a well-formed DNS message so even in the
    // case of other errors we will be returning a DNS response.

    // only handle queries
    match (request.message_type(), request.op_code()) {
        (MessageType::Query, OpCode::Query) => (),
        _ => return dns_error(request, ResponseCode::NotImp).to_vec(),
    }

    // make sure we have one and only one query
    let query = match request.query() {
        Some(query) if request.queries().len() == 1 => query,
        _ => return dns_error(request, ResponseCode::FormErr).to_vec(),
    };

    let result = lookup(query.name(), query.query_type());
    let response = dns_response(request.header(), query, result);
    response.to_vec()
}

#[instrument(skip_all)]
fn handle_json_get(req: Request) -> Result<Response, Error> {
    match handle_json_request(req) {
        Ok(json_response) => Ok(Response::from_status(StatusCode::OK)
            .with_body_text_plain(&json_response)
            .with_content_type(mime::APPLICATION_JSON)),
        Err(error) => Ok(Response::from_status(StatusCode::BAD_REQUEST)
            .with_body_text_plain(&format!("{}\n", error))),
    }
}

#[derive(Serialize)]
struct Params {
    json: String,
}

#[instrument(skip_all)]
fn handle_form_get(req: Request) -> Result<Response, Error> {
    let json_response = match handle_json_request(req) {
        Ok(json_response) => json_response,
        _ => "".to_string(),
    };

    let params = Params {
        json: json_response,
    };

    let template = Handlebars::new().render_template(include_str!("query.html"), &params)?;
    Ok(Response::from_status(StatusCode::OK)
        .with_body_text_plain(&template)
        .with_content_type(mime::TEXT_HTML_UTF_8))
}

fn json_records(records: &[Record]) -> Vec<JsonValue> {
    let json_records: Vec<JsonValue> = records
        .iter()
        .map(|r| {
            json!({
            "name": r.name(),
            // "type": u16::from(r.record_type()),
            "type": r.record_type(),
            "TTL": r.ttl(),
            "data": r.data(),
            })
        })
        .collect();
    json_records
}

fn handle_json_request(req: Request) -> Result<String, Error> {
    let name = req
        .get_query_parameter("name")
        .and_then(|name| Name::from_str_relaxed(name).ok())
        .ok_or(anyhow!("Missing or invalid 'name' parameter"))?;

    let rr_type = req
        .get_query_parameter("type")
        .or_else(|| req.get_query_parameter("rr_type"))
        .or(Some("A"))
        .and_then(|rr_type| RecordType::from_str(&rr_type.to_uppercase()).ok())
        .ok_or(anyhow!("Invalid 'type' parameter"))?;

    let result = lookup(&name, rr_type);
    let response = dns_response(&Header::new(), &Query::query(name, rr_type), result);

    let header = response.header();
    let questions: Vec<JsonValue> = response
        .queries()
        .iter()
        .map(|q| {
            json!({
            "name": q.name(),
            // "type": u16::from(q.query_type()),
            "type": q.query_type()})
        })
        .collect();

    match to_string_pretty(&json!({
        // "Status": response.response_code().low(),
        "Status": response.response_code().to_str(),
        "TC": header.truncated(),
        "RD": header.recursion_desired(),
        "RA": header.recursion_available(),
        "AD": header.authoritative(),
        "CD": header.checking_disabled(),
        "Question": questions,
        "Answer": json_records(response.answers()),
        "Authority": json_records(response.name_servers()),
        "Additional": json_records(response.additionals()),
    })) {
        Ok(json_response) => Ok(json_response),
        _ => Err(anyhow!("JSON encoding error")),
    }
}
fn install_tracing_subscriber() {
    tracing_subscriber::fmt()
        .compact()
        .with_target(false)
        .with_max_level(Level::INFO)
        // .with_max_level(Level::DEBUG)
        .with_span_events(format::FmtSpan::CLOSE)
        .init();
}

#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {
    install_tracing_subscriber();

    info!(
        "{} {} {:?}",
        req.get_method(),
        req.get_url(),
        req.get_header_str(header::CONTENT_TYPE)
    );

    match (
        req.get_method(),
        req.get_path(),
        req.get_header_str(header::CONTENT_TYPE),
    ) {
        (&Method::POST, "/dns-query", Some(MIME_APPLICATION_DNS)) => handle_doh_post(req),
        (&Method::GET, "/dns-query", Some(MIME_APPLICATION_DNS)) => handle_doh_get(req),
        (&Method::GET, "/resolve", ..) => handle_json_get(req),
        (&Method::GET, "/query", ..) => handle_form_get(req),
        (&Method::GET, "/debug", ..) => handle_debug(),
        _ => handle_form_get(req),
    }
}
