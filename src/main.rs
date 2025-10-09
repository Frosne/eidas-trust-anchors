use base64::prelude::*;
use chrono::{DateTime, Utc};
use clap::{Parser, ValueEnum};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufReader, Error, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use xml::EventReader;
use xml::reader::XmlEvent;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, short = 'd')]
    dir: PathBuf,

    #[arg(long, short = 'o', required = true)]
    operations: Vec<Operation>,
}

#[derive(Debug, Clone, Copy, ValueEnum, Eq, PartialEq)]
enum Operation {
    Download,
    Process,
    Compare,
}

static CHROMIUM_ADDITIONAL_CERTS: &'static str = "https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/data/ssl/chrome_root_store/additional.certs?format=TEXT";
static CHROMIUM_ADDITIONAL_CERTS_FILENAME: &'static str = "chromium.additional.certs";
static TRUST_ANCHORS_FILENAME: &'static str = "trust_anchors.pem";

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    if args.operations.contains(&Operation::Download) {
        download_if_not_cached(
            CHROMIUM_ADDITIONAL_CERTS,
            CHROMIUM_ADDITIONAL_CERTS_FILENAME.to_string(),
            &args.dir,
        )?;
        download_lists_of_trust_lists(&args.dir)?;
    }
    if args.operations.contains(&Operation::Process) {
        process_trust_lists(&args.dir)?;
    }
    if args.operations.contains(&Operation::Compare) {
        compare_results(&args.dir)?;
    }
    Ok(())
}

fn uri_to_filename(uri: &str) -> String {
    uri.replace(
        &['/', '<', '>', '&', '*', '~', '[', ']', '{', '}', '$'],
        "+",
    )
}

static USER_AGENT: &'static str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

fn download_if_not_cached(uri: &str, filename: String, dir: &Path) -> std::io::Result<()> {
    let path = dir.join(filename);
    eprintln!("maybe downloading {}...", uri);
    if path.exists() {
        eprintln!("{} already exists - skipping", path.display());
        return Ok(());
    }

    let client = reqwest::blocking::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| Error::new(ErrorKind::Other, e))?;
    let result = client
        .get(uri)
        .send()
        .map_err(|e| Error::new(ErrorKind::Other, e))?;
    let contents = result
        .bytes()
        .map_err(|e| Error::new(ErrorKind::Other, e))?;
    eprintln!("saving to {}...", path.display());
    let mut file = std::fs::File::create(path)?;
    file.write_all(&contents)?;
    Ok(())
}

fn download_lists_of_trust_lists(dir: &Path) -> std::io::Result<()> {
    let root = "https://ec.europa.eu/tools/lotl/eu-lotl.xml".to_string();
    let mut processed: BTreeSet<String> = BTreeSet::new();
    let mut list_of_trust_lists = vec![root];
    while let Some(trust_list) = list_of_trust_lists.pop() {
        if download_if_not_cached(
            trust_list.as_str(),
            uri_to_filename(trust_list.as_str()),
            dir,
        )
        .is_err()
        {
            eprintln!("error - skipping {}", trust_list);
            continue;
        }
        let path = dir.join(uri_to_filename(trust_list.as_str()));
        let trust_list_file = File::open(path)?;
        let trust_list_reader = BufReader::new(trust_list_file);
        let mut parser = EventReader::new(trust_list_reader);
        let Ok(trust_service_status_list) = TrustServiceStatusList::from_xml(&mut parser) else {
            continue;
        };
        for other_tsl_pointer in trust_service_status_list
            .scheme_information
            .pointers_to_other_tsl
            .other_tsl_pointers
            .iter()
        {
            eprintln!("considering {}", other_tsl_pointer.tsl_location);
            if !processed.contains(&other_tsl_pointer.tsl_location) {
                list_of_trust_lists.push(other_tsl_pointer.tsl_location.clone());
            }
        }
        processed.insert(trust_list);
    }
    Ok(())
}

fn process_trust_lists(dir: &Path) -> std::io::Result<()> {
    let mut trust_anchors_out = File::create(dir.join(TRUST_ANCHORS_FILENAME))?;
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if !path.is_dir() {
            process_trust_list(&path, &mut trust_anchors_out)?;
        }
    }
    Ok(())
}

fn ignore<R: Read>(parser: &mut EventReader<R>, tag: &str) {
    let mut depth = 1; // caller has already read opening tag of the element to ignore
    loop {
        match parser.next() {
            Ok(XmlEvent::StartElement { .. }) => {
                depth += 1;
            }
            Ok(XmlEvent::EndElement { name }) => {
                assert!(depth > 0);
                depth -= 1;
                if depth == 0 {
                    assert!(name.local_name.as_str() == tag);
                    break;
                }
            }
            Ok(_) => {}
            Err(e) => panic!("error: {}", e),
        }
    }
}

fn read_string<R: Read>(parser: &mut EventReader<R>, tag: &str) -> String {
    let mut contents = None;
    loop {
        match parser.next() {
            Ok(XmlEvent::StartElement { name, .. }) => {
                panic!("unexpected tag '{}'", name.local_name.as_str());
            }
            Ok(XmlEvent::EndElement { name }) => {
                assert!(name.local_name.as_str() == tag);
                return contents.unwrap();
            }
            Ok(XmlEvent::Characters(value)) => {
                let replaced = contents.replace(value);
                assert!(replaced.is_none());
            }
            Ok(_) => {}
            Err(e) => panic!("error: {}", e),
        }
    }
}

#[derive(Debug)]
struct TrustServiceStatusList {
    scheme_information: SchemeInformation,
    trust_service_provider_list: Option<TrustServiceProviderList>,
}

impl TrustServiceStatusList {
    fn from_xml<R: Read>(
        parser: &mut EventReader<R>,
    ) -> xml::reader::Result<TrustServiceStatusList> {
        let mut scheme_information = None;
        let mut trust_service_provider_list = None;
        loop {
            match parser.next()? {
                XmlEvent::StartElement { name, .. } => {
                    let tag = name.local_name.as_str();
                    match tag {
                        // TODO: This is awkward...
                        // Since this is the root element, it'll be the first tag seen.
                        "TrustServiceStatusList" => {}
                        "SchemeInformation" => {
                            let replaced =
                                scheme_information.replace(SchemeInformation::from_xml(parser));
                            assert!(replaced.is_none());
                        }
                        "TrustServiceProviderList" => {
                            let replaced = trust_service_provider_list
                                .replace(TrustServiceProviderList::from_xml(parser));
                            assert!(replaced.is_none());
                        }
                        "Signature" => ignore(parser, "Signature"),
                        _ => panic!("unhandled tag '{}'", tag),
                    }
                }
                XmlEvent::EndElement { name } => {
                    assert!(name.local_name.as_str() == "TrustServiceStatusList");
                    return Ok(TrustServiceStatusList {
                        scheme_information: scheme_information.unwrap(),
                        trust_service_provider_list,
                    });
                }
                _ => {}
            }
        }
    }
}

#[derive(Debug)]
struct SchemeInformation {
    pointers_to_other_tsl: PointersToOtherTSL,
}

impl SchemeInformation {
    fn from_xml<R: Read>(parser: &mut EventReader<R>) -> SchemeInformation {
        let mut pointers_to_other_tsl = None;
        loop {
            match parser.next() {
                Ok(XmlEvent::StartElement { name, .. }) => {
                    let tag = name.local_name.as_str();
                    match tag {
                        "PointersToOtherTSL" => {
                            let replaced =
                                pointers_to_other_tsl.replace(PointersToOtherTSL::from_xml(parser));
                            assert!(replaced.is_none());
                        }
                        "Signature" => ignore(parser, "Signature"),
                        "DistributionPoints" => ignore(parser, "DistributionPoints"),
                        "HistoricalInformationPeriod" => {
                            ignore(parser, "HistoricalInformationPeriod")
                        }
                        "ListIssueDateTime" => ignore(parser, "ListIssueDateTime"),
                        "NextUpdate" => ignore(parser, "NextUpdate"),
                        "PolicyOrLegalNotice" => ignore(parser, "PolicyOrLegalNotice"),
                        "SchemeInformationURI" => ignore(parser, "SchemeInformationURI"),
                        "SchemeName" => ignore(parser, "SchemeName"),
                        "SchemeOperatorAddress" => ignore(parser, "SchemeOperatorAddress"),
                        "SchemeOperatorName" => ignore(parser, "SchemeOperatorName"),
                        "SchemeTerritory" => ignore(parser, "SchemeTerritory"),
                        "SchemeTypeCommunityRules" => ignore(parser, "SchemeTypeCommunityRules"),
                        "StatusDeterminationApproach" => {
                            ignore(parser, "StatusDeterminationApproach")
                        }
                        "TSLSequenceNumber" => ignore(parser, "TSLSequenceNumber"),
                        "TSLType" => ignore(parser, "TSLType"),
                        "TSLVersionIdentifier" => ignore(parser, "TSLVersionIdentifier"),
                        _ => panic!("unhandled tag '{}'", tag),
                    }
                }
                Ok(XmlEvent::EndElement { name }) => {
                    assert!(name.local_name.as_str() == "SchemeInformation");
                    return SchemeInformation {
                        pointers_to_other_tsl: pointers_to_other_tsl.unwrap(),
                    };
                }
                Ok(_) => {}
                Err(e) => panic!("error: {}", e),
            }
        }
    }
}

#[derive(Debug)]
struct PointersToOtherTSL {
    other_tsl_pointers: Vec<OtherTSLPointer>,
}

impl PointersToOtherTSL {
    fn from_xml<R: Read>(parser: &mut EventReader<R>) -> PointersToOtherTSL {
        let mut other_tsl_pointers = Vec::new();
        loop {
            match parser.next() {
                Ok(XmlEvent::StartElement { name, .. }) => {
                    let tag = name.local_name.as_str();
                    match tag {
                        "OtherTSLPointer" => {
                            other_tsl_pointers.push(OtherTSLPointer::from_xml(parser))
                        }
                        _ => panic!("unhandled tag '{}'", tag),
                    }
                }
                Ok(XmlEvent::EndElement { name }) => {
                    assert!(name.local_name.as_str() == "PointersToOtherTSL");
                    return PointersToOtherTSL { other_tsl_pointers };
                }
                Ok(_) => {}
                Err(e) => panic!("error: {}", e),
            }
        }
    }
}

#[derive(Debug)]
struct OtherTSLPointer {
    tsl_location: String,
}

impl OtherTSLPointer {
    fn from_xml<R: Read>(parser: &mut EventReader<R>) -> OtherTSLPointer {
        let mut tsl_location = None;
        loop {
            match parser.next() {
                Ok(XmlEvent::StartElement { name, .. }) => {
                    let tag = name.local_name.as_str();
                    match tag {
                        "AdditionalInformation" => ignore(parser, "AdditionalInformation"),
                        "ServiceDigitalIdentities" => ignore(parser, "ServiceDigitalIdentities"),
                        "TSLLocation" => {
                            let replaced = tsl_location.replace(read_string(parser, "TSLLocation"));
                            assert!(replaced.is_none());
                        }
                        _ => panic!("unhandled tag '{}'", tag),
                    }
                }
                Ok(XmlEvent::EndElement { name }) => {
                    assert!(name.local_name.as_str() == "OtherTSLPointer");
                    return OtherTSLPointer {
                        tsl_location: tsl_location.unwrap(),
                    };
                }
                Ok(_) => {}
                Err(e) => panic!("error: {}", e),
            }
        }
    }
}

#[derive(Debug)]
struct TrustServiceProviderList {
    trust_service_providers: Vec<TrustServiceProvider>,
}

impl TrustServiceProviderList {
    fn from_xml<R: Read>(parser: &mut EventReader<R>) -> TrustServiceProviderList {
        let mut trust_service_providers = Vec::new();
        loop {
            match parser.next() {
                Ok(XmlEvent::StartElement { name, .. }) => {
                    let tag = name.local_name.as_str();
                    match tag {
                        "TrustServiceProvider" => {
                            trust_service_providers.push(TrustServiceProvider::from_xml(parser))
                        }
                        _ => panic!("unhandled tag '{}'", tag),
                    }
                }
                Ok(XmlEvent::EndElement { name }) => {
                    assert!(name.local_name.as_str() == "TrustServiceProviderList");
                    return TrustServiceProviderList {
                        trust_service_providers,
                    };
                }
                Ok(_) => {}
                Err(e) => panic!("error: {}", e),
            }
        }
    }
}

#[derive(Debug)]
struct TrustServiceProvider {
    tsp_services: Vec<TSPService>,
}

impl TrustServiceProvider {
    fn from_xml<R: Read>(parser: &mut EventReader<R>) -> TrustServiceProvider {
        let mut tsp_services = Vec::new();
        loop {
            match parser.next() {
                Ok(XmlEvent::StartElement { name, .. }) => {
                    let tag = name.local_name.as_str();
                    match tag {
                        "TSPInformation" => ignore(parser, "TSPInformation"),
                        "TSPServices" => {}
                        "TSPService" => tsp_services.push(TSPService::from_xml(parser)),
                        _ => panic!("unhandled tag '{}'", tag),
                    }
                }
                Ok(XmlEvent::EndElement { name }) => {
                    let tag = name.local_name.as_str();
                    match tag {
                        "TSPServices" => {}
                        "TrustServiceProvider" => return TrustServiceProvider { tsp_services },
                        _ => panic!("unexpected tag '{tag}'"),
                    }
                }
                Ok(_) => {}
                Err(e) => panic!("error: {}", e),
            }
        }
    }
}

#[derive(Debug)]
struct TSPService {
    service_history: Option<ServiceHistory>,
    service_information: ServiceInformation,
}

impl TSPService {
    fn from_xml<R: Read>(parser: &mut EventReader<R>) -> TSPService {
        let mut service_history = None;
        let mut service_information = None;
        loop {
            match parser.next() {
                Ok(XmlEvent::StartElement { name, .. }) => {
                    let tag = name.local_name.as_str();
                    match tag {
                        "ServiceHistory" => {
                            let replaced =
                                service_history.replace(ServiceHistory::from_xml(parser));
                            assert!(replaced.is_none());
                        }
                        "ServiceInformation" => {
                            let replaced =
                                service_information.replace(ServiceInformation::from_xml(parser));
                            assert!(replaced.is_none());
                        }
                        _ => panic!("unhandled tag '{}'", tag),
                    }
                }
                Ok(XmlEvent::EndElement { name }) => {
                    assert!(name.local_name.as_str() == "TSPService");
                    return TSPService {
                        service_history,
                        service_information: service_information.unwrap(),
                    };
                }
                Ok(_) => {}
                Err(e) => panic!("error: {}", e),
            }
        }
    }

    fn is_qwacs(&self) -> bool {
        let mut qwacs_statuses = vec![self.service_information.qwacs_status()];
        if let Some(service_history) = self.service_history.as_ref() {
            for service_history_instance in service_history.service_history_instances.iter() {
                qwacs_statuses.push(service_history_instance.qwacs_status());
            }
        }
        let Some(most_recent_qwacs_status) =
            qwacs_statuses.iter().max_by_key(|(_, timestamp)| timestamp)
        else {
            return false;
        };
        match most_recent_qwacs_status {
            (QWACsStatus::Granted, _) => true,
            (QWACsStatus::Withdrawn, _) => false,
            (QWACsStatus::Other, _) => false,
        }
    }
}

#[derive(Debug)]
struct ServiceHistory {
    service_history_instances: Vec<ServiceHistoryInstance>,
}

impl ServiceHistory {
    fn from_xml<R: Read>(parser: &mut EventReader<R>) -> ServiceHistory {
        let mut service_history_instances = Vec::new();
        loop {
            match parser.next() {
                Ok(XmlEvent::StartElement { name, .. }) => {
                    let tag = name.local_name.as_str();
                    match tag {
                        "ServiceHistoryInstance" => {
                            service_history_instances.push(ServiceHistoryInstance::from_xml(parser))
                        }
                        _ => panic!("unhandled tag '{}'", tag),
                    }
                }
                Ok(XmlEvent::EndElement { name }) => {
                    assert!(name.local_name.as_str() == "ServiceHistory");
                    return ServiceHistory {
                        service_history_instances,
                    };
                }
                Ok(_) => {}
                Err(e) => {
                    panic!("error: {}", e);
                }
            }
        }
    }
}

#[derive(Debug)]
struct ServiceHistoryInstance {
    service_digital_identity: ServiceDigitalIdentity,
    service_information_extensions: Option<ServiceInformationExtensions>,
    service_status: String,
    service_type_identifier: String,
    status_starting_time: String,
}

impl ServiceHistoryInstance {
    fn from_xml<R: Read>(parser: &mut EventReader<R>) -> ServiceHistoryInstance {
        let mut service_digital_identity = None;
        let mut service_information_extensions = None;
        let mut service_status = None;
        let mut service_type_identifier = None;
        let mut status_starting_time = None;
        loop {
            match parser.next() {
                Ok(XmlEvent::StartElement { name, .. }) => {
                    let tag = name.local_name.as_str();
                    match tag {
                        "ServiceDigitalIdentity" => {
                            let replaced = service_digital_identity
                                .replace(ServiceDigitalIdentity::from_xml(parser));
                            assert!(replaced.is_none());
                        }
                        "ServiceInformationExtensions" => {
                            let replaced = service_information_extensions
                                .replace(ServiceInformationExtensions::from_xml(parser));
                            assert!(replaced.is_none());
                        }
                        "ServiceName" => ignore(parser, "ServiceName"),
                        "ServiceStatus" => {
                            let replaced =
                                service_status.replace(read_string(parser, "ServiceStatus"));
                            assert!(replaced.is_none());
                        }
                        "ServiceTypeIdentifier" => {
                            let replaced = service_type_identifier
                                .replace(read_string(parser, "ServiceTypeIdentifier"));
                            assert!(replaced.is_none());
                        }
                        "StatusStartingTime" => {
                            let replaced = status_starting_time
                                .replace(read_string(parser, "StatusStartingTime"));
                            assert!(replaced.is_none());
                        }
                        _ => panic!("unhandled tag '{}'", tag),
                    }
                }
                Ok(XmlEvent::EndElement { name }) => {
                    assert!(name.local_name.as_str() == "ServiceHistoryInstance");
                    return ServiceHistoryInstance {
                        service_digital_identity: service_digital_identity.unwrap(),
                        service_information_extensions,
                        service_status: service_status.unwrap(),
                        service_type_identifier: service_type_identifier.unwrap(),
                        status_starting_time: status_starting_time.unwrap(),
                    };
                }
                Ok(_) => {}
                Err(e) => {
                    panic!("error: {}", e);
                }
            }
        }
    }

    fn qwacs_status(&self) -> (QWACsStatus, DateTime<Utc>) {
        QWACsStatus::from_service_information(
            &self.service_information_extensions,
            self.service_type_identifier.as_str(),
            self.service_status.as_str(),
            self.status_starting_time.as_str(),
        )
    }
}

#[derive(Debug)]
struct ServiceInformation {
    service_digital_identity: ServiceDigitalIdentity,
    service_information_extensions: Option<ServiceInformationExtensions>,
    service_name: ServiceName,
    service_status: String,
    service_type_identifier: String,
    status_starting_time: String,
}

enum QWACsStatus {
    Granted,
    Withdrawn,
    Other,
}

impl QWACsStatus {
    fn from_service_information(
        service_information_extensions: &Option<ServiceInformationExtensions>,
        service_type_identifier: &str,
        service_status: &str,
        status_starting_time: &str,
    ) -> (QWACsStatus, DateTime<Utc>) {
        let timestamp = DateTime::parse_from_rfc3339(status_starting_time)
            .unwrap()
            .into();
        let Some(service_information_extensions) = service_information_extensions.as_ref() else {
            return (QWACsStatus::Other, timestamp);
        };
        if service_information_extensions
            .extensions
            .iter()
            .find(|extension| {
                extension
                    .additional_service_information
                    .as_ref()
                    .map_or("", |asi| asi.uri.as_str())
                    == "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication"
            })
            .is_none()
        {
            return (QWACsStatus::Other, timestamp);
        }
        if service_type_identifier != "http://uri.etsi.org/TrstSvc/Svctype/CA/QC" {
            return (QWACsStatus::Other, timestamp);
        }
        if service_status == "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted" {
            return (QWACsStatus::Granted, timestamp);
        }
        if service_status == "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn" {
            return (QWACsStatus::Withdrawn, timestamp);
        }
        (QWACsStatus::Granted, timestamp)
    }
}

impl ServiceInformation {
    fn from_xml<R: Read>(parser: &mut EventReader<R>) -> ServiceInformation {
        let mut service_digital_identity = None;
        let mut service_information_extensions = None;
        let mut service_name = None;
        let mut service_status = None;
        let mut service_type_identifier = None;
        let mut status_starting_time = None;
        loop {
            match parser.next() {
                Ok(XmlEvent::StartElement { name, .. }) => {
                    let tag = name.local_name.as_str();
                    match tag {
                        "ServiceDigitalIdentity" => {
                            let replaced = service_digital_identity
                                .replace(ServiceDigitalIdentity::from_xml(parser));
                            assert!(replaced.is_none());
                        }
                        "ServiceInformationExtensions" => {
                            let replaced = service_information_extensions
                                .replace(ServiceInformationExtensions::from_xml(parser));
                            assert!(replaced.is_none());
                        }
                        "ServiceName" => {
                            let replaced = service_name.replace(ServiceName::from_xml(parser));
                            assert!(replaced.is_none());
                        }
                        "ServiceStatus" => {
                            let replaced =
                                service_status.replace(read_string(parser, "ServiceStatus"));
                            assert!(replaced.is_none());
                        }
                        "ServiceTypeIdentifier" => {
                            let replaced = service_type_identifier
                                .replace(read_string(parser, "ServiceTypeIdentifier"));
                            assert!(replaced.is_none());
                        }
                        "StatusStartingTime" => {
                            let replaced = status_starting_time
                                .replace(read_string(parser, "StatusStartingTime"));
                            assert!(replaced.is_none());
                        }
                        "SchemeServiceDefinitionURI" => {
                            ignore(parser, "SchemeServiceDefinitionURI")
                        }
                        "TSPServiceDefinitionURI" => ignore(parser, "TSPServiceDefinitionURI"),
                        "ServiceSupplyPoints" => ignore(parser, "ServiceSupplyPoints"),
                        _ => panic!("unhandled tag '{}'", tag),
                    }
                }
                Ok(XmlEvent::EndElement { name }) => {
                    assert!(name.local_name.as_str() == "ServiceInformation");
                    return ServiceInformation {
                        service_digital_identity: service_digital_identity.unwrap(),
                        service_information_extensions,
                        service_name: service_name.unwrap(),
                        service_status: service_status.unwrap(),
                        service_type_identifier: service_type_identifier.unwrap(),
                        status_starting_time: status_starting_time.unwrap(),
                    };
                }
                Ok(_) => {}
                Err(e) => {
                    panic!("error: {}", e);
                }
            }
        }
    }

    fn qwacs_status(&self) -> (QWACsStatus, DateTime<Utc>) {
        QWACsStatus::from_service_information(
            &self.service_information_extensions,
            self.service_type_identifier.as_str(),
            self.service_status.as_str(),
            self.status_starting_time.as_str(),
        )
    }
}

#[derive(Debug)]
struct ServiceDigitalIdentity {
    digital_ids: Vec<DigitalId>,
}

impl ServiceDigitalIdentity {
    fn from_xml<R: Read>(parser: &mut EventReader<R>) -> ServiceDigitalIdentity {
        let mut digital_ids = Vec::new();
        loop {
            match parser.next() {
                Ok(XmlEvent::StartElement { name, .. }) => {
                    let tag = name.local_name.as_str();
                    match tag {
                        "DigitalId" => digital_ids.push(DigitalId::from_xml(parser)),
                        _ => panic!("unhandled tag '{}'", tag),
                    }
                }
                Ok(XmlEvent::EndElement { name }) => {
                    assert!(name.local_name.as_str() == "ServiceDigitalIdentity");
                    return ServiceDigitalIdentity { digital_ids };
                }
                Ok(_) => {}
                Err(e) => {
                    panic!("error: {}", e);
                }
            }
        }
    }

    fn certificate(&self, ski_to_certificate: &BTreeMap<String, String>) -> Option<String> {
        for digital_id in self.digital_ids.iter() {
            match digital_id {
                DigitalId::X509Certificate(certificate) => return Some(certificate.clone()),
                DigitalId::X509SKI(ski) => {
                    return ski_to_certificate
                        .get(&ski.clone())
                        .map(|certificate| certificate.clone());
                }
                _ => {}
            }
        }
        None
    }
}

#[derive(Debug)]
enum DigitalId {
    X509SKI(String),
    X509Certificate(String),
    None,
}

impl DigitalId {
    fn from_xml<R: Read>(parser: &mut EventReader<R>) -> DigitalId {
        let mut digital_id = None;
        loop {
            match parser.next() {
                Ok(XmlEvent::StartElement { name, .. }) => {
                    let tag = name.local_name.as_str();
                    match tag {
                        "X509SKI" => {
                            let replaced = digital_id
                                .replace(DigitalId::X509SKI(read_string(parser, "X509SKI")));
                            assert!(replaced.is_none());
                        }
                        "X509Certificate" => {
                            let replaced = digital_id.replace(DigitalId::X509Certificate(
                                normalize_certificate(read_string(parser, "X509Certificate")),
                            ));
                            assert!(replaced.is_none());
                        }
                        "X509SubjectName" => ignore(parser, "X509SubjectName"),
                        "Other" => ignore(parser, "Other"),
                        _ => panic!("unhandled tag '{}'", tag),
                    }
                }
                Ok(XmlEvent::EndElement { name }) => {
                    assert!(name.local_name.as_str() == "DigitalId");
                    return digital_id.unwrap_or(DigitalId::None);
                }
                Ok(_) => {}
                Err(e) => {
                    panic!("error: {}", e);
                }
            }
        }
    }
}

#[derive(Debug)]
struct ServiceInformationExtensions {
    extensions: Vec<Extension>,
}

impl ServiceInformationExtensions {
    fn from_xml<R: Read>(parser: &mut EventReader<R>) -> ServiceInformationExtensions {
        let mut extensions = Vec::new();
        loop {
            match parser.next() {
                Ok(XmlEvent::StartElement { name, .. }) => {
                    let tag = name.local_name.as_str();
                    match tag {
                        "Extension" => extensions.push(Extension::from_xml(parser)),
                        _ => panic!("unhandled tag '{}'", tag),
                    }
                }
                Ok(XmlEvent::EndElement { name }) => {
                    assert!(name.local_name.as_str() == "ServiceInformationExtensions");
                    return ServiceInformationExtensions { extensions };
                }
                Ok(_) => {}
                Err(e) => {
                    panic!("error: {}", e);
                }
            }
        }
    }
}

#[derive(Debug)]
struct Extension {
    additional_service_information: Option<AdditionalServiceInformation>,
}

impl Extension {
    fn from_xml<R: Read>(parser: &mut EventReader<R>) -> Extension {
        let mut additional_service_information = None;
        loop {
            match parser.next() {
                Ok(XmlEvent::StartElement { name, .. }) => {
                    let tag = name.local_name.as_str();
                    match tag {
                        "AdditionalServiceInformation" => {
                            let replaced = additional_service_information
                                .replace(AdditionalServiceInformation::from_xml(parser));
                            assert!(replaced.is_none());
                        }
                        "Qualifications" => ignore(parser, "Qualifications"),
                        "TakenOverBy" => ignore(parser, "TakenOverBy"),
                        "URLContentTypeAndAuthorizedServiceList" => {
                            ignore(parser, "URLContentTypeAndAuthorizedServiceList")
                        }
                        "ExpiredCertsRevocationInfo" => {
                            ignore(parser, "ExpiredCertsRevocationInfo")
                        }
                        _ => panic!("unhandled tag '{}'", tag),
                    }
                }
                Ok(XmlEvent::EndElement { name }) => {
                    assert!(name.local_name.as_str() == "Extension");
                    return Extension {
                        additional_service_information,
                    };
                }
                Ok(_) => {}
                Err(e) => panic!("error: {}", e),
            }
        }
    }
}

#[derive(Debug, Default)]
struct AdditionalServiceInformation {
    uri: String,
}

impl AdditionalServiceInformation {
    fn from_xml<R: Read>(parser: &mut EventReader<R>) -> AdditionalServiceInformation {
        let mut uri = None;
        loop {
            match parser.next() {
                Ok(XmlEvent::StartElement { name, .. }) => {
                    let tag = name.local_name.as_str();
                    match tag {
                        "URI" => {
                            let replaced = uri.replace(read_string(parser, "URI"));
                            assert!(replaced.is_none());
                        }
                        _ => panic!("unhandled tag '{}'", tag),
                    }
                }
                Ok(XmlEvent::EndElement { name }) => {
                    assert!(name.local_name.as_str() == "AdditionalServiceInformation");
                    return AdditionalServiceInformation { uri: uri.unwrap() };
                }
                Ok(_) => {}
                Err(e) => {
                    panic!("error: {}", e);
                }
            }
        }
    }
}

#[derive(Debug)]
struct ServiceName {
    names: Vec<String>,
}

impl ServiceName {
    fn from_xml<R: Read>(parser: &mut EventReader<R>) -> ServiceName {
        let mut names = Vec::new();
        loop {
            match parser.next() {
                Ok(XmlEvent::StartElement { name, .. }) => {
                    let tag = name.local_name.as_str();
                    match tag {
                        "Name" => names.push(read_string(parser, "Name")),
                        _ => panic!("unhandled tag '{}'", tag),
                    }
                }
                Ok(XmlEvent::EndElement { name }) => {
                    assert!(name.local_name.as_str() == "ServiceName");
                    return ServiceName { names };
                }
                Ok(_) => {}
                Err(e) => {
                    panic!("error: {}", e);
                }
            }
        }
    }

    fn name(&self) -> &str {
        self.names.last().unwrap().as_str()
    }
}

fn normalize_certificate(certificate: String) -> String {
    let mut lines = vec!["-----BEGIN CERTIFICATE-----".to_string()];
    for chunk in certificate.replace("\n", "").as_bytes().chunks(64) {
        let line = String::from_utf8(chunk.to_vec()).unwrap();
        lines.push(line);
    }
    lines.push("-----END CERTIFICATE-----".to_string());
    lines.join("\n")
}

fn process_trust_list(path: &Path, trust_anchors_out: &mut File) -> std::io::Result<()> {
    let trust_list_file = File::open(path)?;
    let trust_list_reader = BufReader::new(trust_list_file);
    let mut parser = EventReader::new(trust_list_reader);
    let Ok(trust_service_status_list) = TrustServiceStatusList::from_xml(&mut parser) else {
        return Ok(());
    };
    let Some(trust_service_provider_list) = trust_service_status_list
        .trust_service_provider_list
        .as_ref()
    else {
        return Ok(());
    };
    for trust_service_provider in trust_service_provider_list.trust_service_providers.iter() {
        let mut ski_to_certificate = BTreeMap::new();
        for tsp_service in trust_service_provider.tsp_services.iter() {
            let mut certificate = None;
            let mut ski = None;
            for digital_id in tsp_service
                .service_information
                .service_digital_identity
                .digital_ids
                .iter()
            {
                match &digital_id {
                    DigitalId::X509Certificate(value) => {
                        // TODO: pick the "best" certificate
                        let _ = certificate.replace(value.clone());
                    }
                    DigitalId::X509SKI(value) => {
                        // TODO: assert these are the same?
                        let _ = ski.replace(value.clone());
                    }
                    _ => {}
                }
            }
            if let Some(service_history) = tsp_service.service_history.as_ref() {
                for service_history_instance in service_history.service_history_instances.iter() {
                    for digital_id in service_history_instance
                        .service_digital_identity
                        .digital_ids
                        .iter()
                    {
                        match &digital_id {
                            DigitalId::X509Certificate(value) => {
                                // TODO: pick the "best" certificate
                                let _ = certificate.replace(value.clone());
                            }
                            DigitalId::X509SKI(value) => {
                                // TODO: assert these are the same?
                                let _ = ski.replace(value.clone());
                            }
                            _ => {}
                        }
                    }
                }
            }
            let Some(certificate) = certificate else {
                continue;
            };
            let Some(ski) = ski else {
                continue;
            };
            let _ = ski_to_certificate.insert(ski, certificate);
        }
        for tsp_service in trust_service_provider.tsp_services.iter() {
            if tsp_service.is_qwacs() {
                let service_name = tsp_service
                    .service_information
                    .service_name
                    .name()
                    .replace(r#"""#, r#"\""#);
                trust_anchors_out
                    .write_all(format!(r#"TSP service name: "{service_name}""#).as_bytes())?;
                trust_anchors_out.write_all("\n".as_bytes())?;
                let certificate = tsp_service
                    .service_information
                    .service_digital_identity
                    .certificate(&ski_to_certificate)
                    .unwrap();
                trust_anchors_out.write_all(certificate.as_bytes())?;
                trust_anchors_out.write_all("\n".as_bytes())?;
            }
        }
    }
    Ok(())
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Debug, Clone)]
struct TrustAnchor {
    tsp_service_name: String,
    pem: String,
}

impl TrustAnchor {
    fn new(tsp_service_name: String, pem: String) -> TrustAnchor {
        TrustAnchor {
            tsp_service_name,
            pem,
        }
    }
}

impl std::fmt::Display for TrustAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "TSP service name: {}", self.tsp_service_name)?;
        write!(f, "{}", self.pem)
    }
}

fn parse_trust_anchors(trust_anchors_text: String) -> BTreeSet<TrustAnchor> {
    let mut maybe_tsp_service_name: Option<String> = None;
    let mut maybe_pem = None;
    let mut trust_anchors = BTreeSet::new();
    for line in trust_anchors_text.lines() {
        match line {
            "-----BEGIN CERTIFICATE-----" => {
                maybe_pem.replace(vec![line]);
            }
            "-----END CERTIFICATE-----" => {
                let mut pem = maybe_pem
                    .take()
                    .expect("END CERTIFICATE without BEGIN CERTIFICATE?");
                pem.push(line);
                if let Some(tsp_service_name) = maybe_tsp_service_name.take() {
                    let trust_anchor = TrustAnchor::new(tsp_service_name.clone(), pem.join("\n"));
                    if !trust_anchors.insert(trust_anchor) {
                        eprintln!("duplicate TSP? ({})", tsp_service_name);
                    }
                } else {
                    eprintln!("no TSP service name -> probably Google certificate");
                }
            }
            _ => {
                if let Some(pem) = maybe_pem.as_mut() {
                    pem.push(line);
                } else if line.starts_with("TSP service name: ") {
                    if let Some(tsp_service_name) = line.split("TSP service name: ").last() {
                        let replaced = maybe_tsp_service_name.replace(tsp_service_name.to_string());
                        assert!(replaced.is_none());
                    }
                }
            }
        }
    }
    trust_anchors
}

fn compare_results(dir: &Path) -> std::io::Result<()> {
    let chromium_additional_certs_base64 =
        std::fs::read_to_string(dir.join(CHROMIUM_ADDITIONAL_CERTS_FILENAME))?;
    let chromium_additional_certs_bytes = BASE64_STANDARD
        .decode(chromium_additional_certs_base64)
        .map_err(|e| Error::new(ErrorKind::Other, e))?;
    let chromium_additional_certs = String::from_utf8(chromium_additional_certs_bytes)
        .map_err(|e| Error::new(ErrorKind::Other, e))?;
    let chromium_trust_anchors = parse_trust_anchors(chromium_additional_certs);
    let trust_anchors = std::fs::read_to_string(dir.join(TRUST_ANCHORS_FILENAME))?;
    let trust_anchors = parse_trust_anchors(trust_anchors);

    eprintln!("===== in Chromium but not Firefox =====");
    for chromium_extra in chromium_trust_anchors.difference(&trust_anchors) {
        eprintln!("{}", chromium_extra);
    }
    eprintln!("===== in Firefox but not Chromium =====");
    for firefox_extra in trust_anchors.difference(&chromium_trust_anchors) {
        eprintln!("{}", firefox_extra);
    }

    Ok(())
}
