use winnow::{
    binary::{le_u16, le_u32, length_and_then, length_take},
    combinator::eof,
    token::take,
    PResult, Parser,
};

use crate::*;

pub const HEADER_SIZE: usize = 48;
pub const REPORT_SIZE: usize = 384;

pub(crate) fn parse_quote<'i>(input: &mut &'i [u8]) -> PResult<Quote<'i>> {
    let saved_input = *input;

    let HeaderExt { header, ak_ty } = parse_header_ext(input)?;
    let isv_report = parse_report_body(input)?;
    let signature = length_and_then(le_u32, parse_signature(ak_ty)).parse_next(input)?;
    let _ = eof(input)?;

    let signed_message = &saved_input[..(HEADER_SIZE + REPORT_SIZE)];

    Ok(Quote {
        header,
        isv_report,
        signature,
        signed_message,
    })
}

struct HeaderExt<'a> {
    header: Header<'a>,
    ak_ty: u16,
}

fn parse_header_ext<'i>(input: &mut &'i [u8]) -> PResult<HeaderExt<'i>> {
    let version = le_u16(input)?;
    let ak_ty = le_u16(input)?;
    let _reserved_1 = take(4usize).parse_next(input)?;
    let qe_svn = le_u16(input)?;
    let pce_svn = le_u16(input)?;
    let qe_vendor_id = take(16usize).parse_next(input)?;
    let user_data = take(20usize).parse_next(input)?;

    Ok(HeaderExt {
        header: Header {
            version,
            qe_svn,
            pce_svn,
            qe_vendor_id,
            user_data,
        },
        ak_ty,
    })
}

fn parse_report_body<'i>(input: &mut &'i [u8]) -> PResult<ReportBody<'i>> {
    let saved_input = *input;

    let cpu_svn = take(16usize).parse_next(input)?;
    let miscselect = le_u32(input)?;
    let _reserved_1 = take(28usize).parse_next(input)?;
    let attributes = take(16usize).parse_next(input)?;
    let mrenclave = take(32usize).parse_next(input)?;
    let _reserved_2 = take(32usize).parse_next(input)?;
    let mrsigner = take(32usize).parse_next(input)?;
    let _reserved_3 = take(96usize).parse_next(input)?;
    let isv_prod_id = le_u16(input)?;
    let isv_svn = le_u16(input)?;
    let _reserved_4 = take(60usize).parse_next(input)?;
    let report_data = take(64usize).parse_next(input)?;

    let signed_message = &saved_input[..REPORT_SIZE];

    Ok(ReportBody {
        cpu_svn,
        miscselect,
        attributes,
        mrenclave,
        mrsigner,
        isv_prod_id,
        isv_svn,
        report_data,
        signed_message,
    })
}

fn parse_signature(
    _attestation_key_type: u16,
) -> impl for<'i> Fn(&mut &'i [u8]) -> PResult<Signature<'i>> {
    |input| {
        let isv_report_signature = take(64usize).parse_next(input)?;
        let attestation_key = take(64usize).parse_next(input)?;
        let qe_report = parse_report_body(input)?;
        let qe_report_signature = take(64usize).parse_next(input)?;
        let qe_authentication_data = length_take(le_u16).parse_next(input)?;
        let qe_certification_data_type = le_u16.verify(is_valid_cd_type).parse_next(input)?;
        let qe_certification_data =
            length_and_then(le_u32, parse_qe_cd(qe_certification_data_type)).parse_next(input)?;

        Ok(Signature::EcdsaP256 {
            isv_report_signature,
            attestation_key,
            qe_report,
            qe_report_signature,
            qe_authentication_data,
            qe_certification_data,
        })
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)] // The macro inserts a ref and rustc won't deref it.
fn is_valid_cd_type(t: &u16) -> bool {
    *t >= 1 && *t <= 5 && *t != 4
}

fn parse_ppid_cd<'a, F>(kind: F) -> impl Fn(&mut &'a [u8]) -> PResult<QeCertificationData<'a>>
where
    F: Fn(&'a [u8]) -> Ppid<'a> + Copy,
{
    move |input| {
        let ppid = take(384usize).map(kind).parse_next(input)?;
        let cpu_svn = take(16usize).parse_next(input)?;
        let pce_svn = le_u16(input)?;
        let pce_id = le_u16(input)?;

        Ok(QeCertificationData::Ppid {
            ppid,
            cpu_svn,
            pce_svn,
            pce_id,
        })
    }
}

fn parse_qe_cd(kind: u16) -> impl for<'i> Fn(&mut &'i [u8]) -> PResult<QeCertificationData<'i>> {
    move |i| match kind {
        1 => parse_ppid_cd(Ppid::Clear)(i),
        2 => parse_ppid_cd(Ppid::Enc2048)(i),
        3 => parse_ppid_cd(Ppid::Enc3072)(i),
        5 => Ok(QeCertificationData::CertChain(i)),
        _ => unreachable!(),
    }
}
