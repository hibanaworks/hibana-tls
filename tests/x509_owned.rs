use hibana_tls::x509::{name::Identity,verify};
macro_rules! cert {($name:literal)=>{include_bytes!(concat!("vectors/x509-owned/",$name,".der")).as_slice()}}
#[test]
fn real_signed_name_constraints_path_length_and_critical_extensions(){
    let root=cert!("root");
    let cases=[
        (cert!("permitted-leaf"),[cert!("permitted-ca1"),cert!("permitted-ca0")],true),
        (cert!("excluded-leaf"),[cert!("excluded-ca1"),cert!("excluded-ca0")],false),
        (cert!("pathzero-leaf"),[cert!("pathzero-ca1"),cert!("pathzero-ca0")],false),
        (cert!("unknown-leaf"),[cert!("unknown-ca1"),cert!("unknown-ca0")],false),
    ];
    for (leaf,intermediates,expected) in cases {
        let result=verify::server(leaf,&intermediates,&[root],Identity::Dns("server.allowed.test"),1800000000);
        assert_eq!(result.is_ok(),expected,"{:?}",result.err());
        let reversed=[intermediates[1],intermediates[0]];
        assert_eq!(verify::server(leaf,&reversed,&[root],Identity::Dns("server.allowed.test"),1800000000).is_ok(),expected);
    }
}
#[test]
fn direct_trust_requires_actual_name_eku_and_signature(){
    let root=cert!("root");
    for (leaf,expected) in [(cert!("direct-valid"),true),(cert!("direct-clientonly"),false),(cert!("direct-unknown"),false)] {
        assert_eq!(verify::server(leaf,&[],&[root],Identity::Dns("server.allowed.test"),1800000000).is_ok(),expected);
    }
    assert!(verify::server(cert!("direct-wildcard"),&[],&[root],Identity::Dns("x.allowed.test"),1800000000).is_ok());
    assert!(verify::server(cert!("direct-wildcard"),&[],&[root],Identity::Dns("x.y.allowed.test"),1800000000).is_err());
    assert!(verify::server(cert!("direct-ip"),&[],&[root],Identity::try_from("127.0.0.1").unwrap(),1800000000).is_ok());
    assert!(verify::server(cert!("direct-ip"),&[],&[root],Identity::try_from("127.0.0.2").unwrap(),1800000000).is_err());
    let mut bad=cert!("direct-valid").to_vec();let end=bad.len()-1;bad[end]^=1;
    assert!(verify::server(&bad,&[],&[root],Identity::Dns("server.allowed.test"),1800000000).is_err());
}

#[test]
fn unchanged_runner_nine_certificate_chain_requires_valid_identity_and_trust() {
    let root = cert!("runner-amplification/root");
    let leaf = cert!("runner-amplification/chain-0");
    let chain = [cert!("runner-amplification/chain-1"),cert!("runner-amplification/chain-2"),cert!("runner-amplification/chain-3"),cert!("runner-amplification/chain-4"),cert!("runner-amplification/chain-5"),cert!("runner-amplification/chain-6"),cert!("runner-amplification/chain-7"),cert!("runner-amplification/chain-8")];
    assert!(verify::server(leaf,&chain,&[root],Identity::Dns("server"),1791507245).is_ok());
    assert!(verify::server(leaf,&chain,&[root],Identity::Dns("wrong.example"),1791507245).is_err());
    assert!(verify::server(leaf,&chain,&[cert!("root")],Identity::Dns("server"),1791507245).is_err());
    assert!(verify::server(leaf,&chain,&[root],Identity::Dns("server"),1800000000).is_err());
    let mut corrupted=leaf.to_vec();let end=corrupted.len()-1;corrupted[end]^=1;
    assert!(verify::server(&corrupted,&chain,&[root],Identity::Dns("server"),1791507245).is_err());
}
