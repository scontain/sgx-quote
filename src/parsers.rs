use winnow::{
    binary::{le_u16, le_u32, length_and_then, length_take},
    combinator::eof,
    token::take,
    PResult, Parser,
};

use crate::*;

pub const HEADER_SIZE: usize = 48;
pub const REPORT_SIZE: usize = 384;

impl<'i> Quote<'i> {
    pub(crate) fn parse_impl(input: &mut &'i [u8]) -> PResult<Self> {
        let saved_input = *input;

        let HeaderExt { header, ak_ty } = HeaderExt::parse(input)?;
        let isv_report = ReportBody::parse(input)?;
        let signature = length_and_then(le_u32, Signature::parse(ak_ty)).parse_next(input)?;
        let _ = eof(input)?;

        let signed_message = &saved_input[..(HEADER_SIZE + REPORT_SIZE)];

        Ok(Self {
            header,
            isv_report,
            signature,
            signed_message,
        })
    }
}

struct HeaderExt<'a> {
    header: Header<'a>,
    ak_ty: u16,
}

impl<'i> HeaderExt<'i> {
    fn parse(input: &mut &'i [u8]) -> PResult<Self> {
        let version = le_u16(input)?;
        let ak_ty = le_u16(input)?;
        let _reserved_1 = take(4usize).parse_next(input)?;
        let qe_svn = le_u16(input)?;
        let pce_svn = le_u16(input)?;
        let qe_vendor_id = take(16usize).parse_next(input)?;
        let user_data = take(20usize).parse_next(input)?;

        Ok(Self {
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
}

impl<'i> ReportBody<'i> {
    fn parse(input: &mut &'i [u8]) -> PResult<Self> {
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

        Ok(Self {
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
}

impl<'i> Signature<'i> {
    fn parse(_attestation_key_type: u16) -> impl Fn(&mut &'i [u8]) -> PResult<Self> {
        |input| {
            let isv_report_signature = take(64usize).parse_next(input)?;
            let attestation_key = take(64usize).parse_next(input)?;
            let qe_report = ReportBody::parse(input)?;
            let qe_report_signature = take(64usize).parse_next(input)?;
            let qe_authentication_data = length_take(le_u16).parse_next(input)?;
            let qe_certification_data_type = le_u16.verify(is_valid_cd_type).parse_next(input)?;
            let qe_certification_data = length_and_then(
                le_u32,
                QeCertificationData::parse(qe_certification_data_type),
            )
            .parse_next(input)?;

            Ok(Self::EcdsaP256 {
                isv_report_signature,
                attestation_key,
                qe_report,
                qe_report_signature,
                qe_authentication_data,
                qe_certification_data,
            })
        }
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)] // The macro inserts a ref and rustc won't deref it.
fn is_valid_cd_type(t: &u16) -> bool {
    *t >= 1 && *t <= 5 && *t != 4
}

impl<'i> QeCertificationData<'i> {
    fn parse(kind: u16) -> impl Fn(&mut &'i [u8]) -> PResult<Self> {
        move |input| match kind {
            1 => Self::parse_ppid(Ppid::Clear)(input),
            2 => Self::parse_ppid(Ppid::Enc2048)(input),
            3 => Self::parse_ppid(Ppid::Enc3072)(input),
            5 => Ok(Self::CertChain(input)),
            _ => unreachable!(),
        }
    }

    fn parse_ppid<F>(kind: F) -> impl Fn(&mut &'i [u8]) -> PResult<Self>
    where
        F: Fn(&'i [u8]) -> Ppid<'i> + Copy,
    {
        move |input| {
            let ppid = take(384usize).map(kind).parse_next(input)?;
            let cpu_svn = take(16usize).parse_next(input)?;
            let pce_svn = le_u16(input)?;
            let pce_id = le_u16(input)?;

            Ok(Self::Ppid {
                ppid,
                cpu_svn,
                pce_svn,
                pce_id,
            })
        }
    }
}
