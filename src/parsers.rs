use winnow::{
    binary::{le_u16, le_u32},
    bytes::take,
    combinator::eof,
    multi::{length_data, length_value},
    IResult, Parser,
};

use crate::*;

pub const HEADER_SIZE: usize = 48;
pub const REPORT_SIZE: usize = 384;

pub(crate) fn parse_quote(input: &[u8]) -> IResult<&[u8], Quote> {
    let (i, HeaderExt { header, ak_ty }) = parse_header_ext(input)?;
    let (i, isv_report) = parse_report_body(i)?;
    let (i, signature) = length_value(le_u32, parse_signature(ak_ty)).parse_next(i)?;
    let (i, _) = eof(i)?;
    Ok((
        i,
        Quote {
            header,
            isv_report,
            signature,
            signed_message: &input[..(HEADER_SIZE + REPORT_SIZE)],
        },
    ))
}

struct HeaderExt<'a> {
    header: Header<'a>,
    ak_ty: u16,
}

fn parse_header_ext(input: &[u8]) -> IResult<&[u8], HeaderExt> {
    let (i, version) = le_u16(input)?;
    let (i, ak_ty) = le_u16(i)?;
    let (i, _reserved_1) = take(4usize).parse_next(i)?;
    let (i, qe_svn) = le_u16(i)?;
    let (i, pce_svn) = le_u16(i)?;
    let (i, qe_vendor_id) = take(16usize).parse_next(i)?;
    let (i, user_data) = take(20usize).parse_next(i)?;

    Ok((
        i,
        HeaderExt {
            header: Header {
                version,
                qe_svn,
                pce_svn,
                qe_vendor_id,
                user_data,
            },
            ak_ty,
        },
    ))
}

fn parse_report_body(input: &[u8]) -> IResult<&[u8], ReportBody> {
    let (i, cpu_svn) = take(16usize).parse_next(input)?;
    let (i, miscselect) = le_u32(i)?;
    let (i, _reserved_1) = take(28usize).parse_next(i)?;
    let (i, attributes) = take(16usize).parse_next(i)?;
    let (i, mrenclave) = take(32usize).parse_next(i)?;
    let (i, _reserved_2) = take(32usize).parse_next(i)?;
    let (i, mrsigner) = take(32usize).parse_next(i)?;
    let (i, _reserved_3) = take(96usize).parse_next(i)?;
    let (i, isv_prod_id) = le_u16(i)?;
    let (i, isv_svn) = le_u16(i)?;
    let (i, _reserved_4) = take(60usize).parse_next(i)?;
    let (i, report_data) = take(64usize).parse_next(i)?;

    Ok((
        i,
        ReportBody {
            cpu_svn,
            miscselect,
            attributes,
            mrenclave,
            mrsigner,
            isv_prod_id,
            isv_svn,
            report_data,
            signed_message: &input[..REPORT_SIZE],
        },
    ))
}

fn parse_signature(_attestation_key_type: u16) -> impl Fn(&[u8]) -> IResult<&[u8], Signature> {
    |input: &[u8]| {
        let (i, isv_report_signature) = take(64usize).parse_next(input)?;
        let (i, attestation_key) = take(64usize).parse_next(i)?;
        let (i, qe_report) = parse_report_body(i)?;
        let (i, qe_report_signature) = take(64usize).parse_next(i)?;
        let (i, qe_authentication_data) = length_data(le_u16).parse_next(i)?;
        let (i, qe_certification_data_type) = le_u16.verify(is_valid_cd_type).parse_next(i)?;
        let (i, qe_certification_data) =
            length_value(le_u32, parse_qe_cd(qe_certification_data_type)).parse_next(i)?;
        Ok((
            i,
            Signature::EcdsaP256 {
                isv_report_signature,
                attestation_key,
                qe_report,
                qe_report_signature,
                qe_authentication_data,
                qe_certification_data,
            },
        ))
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)] // The macro inserts a ref and rustc won't deref it.
fn is_valid_cd_type(t: &u16) -> bool {
    *t >= 1 && *t <= 5 && *t != 4
}

fn parse_ppid_cd<'a, F>(kind: F) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], QeCertificationData<'a>>
where
    F: Fn(&'a [u8]) -> Ppid<'a> + Copy,
{
    move |input| {
        let (i, ppid) = take(384usize).map(kind).parse_next(input)?;
        let (i, cpu_svn) = take(16usize).parse_next(i)?;
        let (i, pce_svn) = le_u16(i)?;
        let (i, pce_id) = le_u16(i)?;
        Ok((
            i,
            QeCertificationData::Ppid {
                ppid,
                cpu_svn,
                pce_svn,
                pce_id,
            },
        ))
    }
}

fn parse_qe_cd(kind: u16) -> impl Fn(&[u8]) -> IResult<&[u8], QeCertificationData> {
    move |i| match kind {
        1 => parse_ppid_cd(Ppid::Clear)(i),
        2 => parse_ppid_cd(Ppid::Enc2048)(i),
        3 => parse_ppid_cd(Ppid::Enc3072)(i),
        5 => Ok((&[], QeCertificationData::CertChain(i))),
        _ => unreachable!(),
    }
}
