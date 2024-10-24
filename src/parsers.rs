use nom::{
    bytes::complete::take,
    combinator::{eof, map, verify},
    multi::{length_data, length_value},
    number::complete::{le_u16, le_u32},
    IResult,
};

use crate::*;

pub const HEADER_SIZE: usize = 48;
pub const REPORT_SIZE: usize = 384;

pub(crate) fn parse_quote(input: &[u8]) -> IResult<&[u8], Quote> {
    let (i, HeaderExt { header, ak_ty }) = parse_header_ext(input)?;
    let (i, isv_report) = parse_report_body(i)?;
    let (i, signature) = length_value(le_u32, |input| parse_signature(input, ak_ty))(i)?;
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
    let (i, _reserved_1) = take(4usize)(i)?;
    let (i, qe_svn) = le_u16(i)?;
    let (i, pce_svn) = le_u16(i)?;
    let (i, qe_vendor_id) = take(16usize)(i)?;
    let (i, user_data) = take(20usize)(i)?;

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
    let (i, cpu_svn) = take(16usize)(input)?;
    let (i, miscselect) = le_u32(i)?;
    let (i, _reserved_1) = take(28usize)(i)?;
    let (i, attributes) = take(16usize)(i)?;
    let (i, mrenclave) = take(32usize)(i)?;
    let (i, _reserved_2) = take(32usize)(i)?;
    let (i, mrsigner) = take(32usize)(i)?;
    let (i, _reserved_3) = take(96usize)(i)?;
    let (i, isv_prod_id) = le_u16(i)?;
    let (i, isv_svn) = le_u16(i)?;
    let (i, _reserved_4) = take(60usize)(i)?;
    let (i, report_data) = take(64usize)(i)?;

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

fn parse_signature(input: &[u8], _attestation_key_type: u16) -> IResult<&[u8], Signature> {
    let (i, isv_report_signature) = take(64usize)(input)?;
    let (i, attestation_key) = take(64usize)(i)?;
    let (i, qe_report) = parse_report_body(i)?;
    let (i, qe_report_signature) = take(64usize)(i)?;
    let (i, qe_authentication_data) = length_data(le_u16)(i)?;
    let (i, qe_certification_data_type) = verify(le_u16, is_valid_cd_type)(i)?;
    let (i, qe_certification_data) = length_value(le_u32, |input| {
        parse_qe_cd(input, qe_certification_data_type)
    })(i)?;
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

#[allow(clippy::trivially_copy_pass_by_ref)] // The macro inserts a ref and rustc won't deref it.
fn is_valid_cd_type(t: &u16) -> bool {
    *t >= 1 && *t <= 5 && *t != 4
}

fn parse_ppid_cd<'a>(
    input: &'a [u8],
    kind: impl FnMut(&'a [u8]) -> Ppid<'a>,
) -> IResult<&'a [u8], QeCertificationData<'a>> {
    let (i, ppid) = map(take(384usize), kind)(input)?;
    let (i, cpu_svn) = take(16usize)(i)?;
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

fn parse_qe_cd(i: &[u8], kind: u16) -> IResult<&[u8], QeCertificationData> {
    match kind {
        1 => parse_ppid_cd(i, Ppid::Clear),
        2 => parse_ppid_cd(i, Ppid::Enc2048),
        3 => parse_ppid_cd(i, Ppid::Enc3072),
        5 => Ok((&[], QeCertificationData::CertChain(i))),
        _ => unreachable!(),
    }
}
