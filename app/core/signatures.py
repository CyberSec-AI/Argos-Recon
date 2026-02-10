from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple

@dataclass(frozen=True)
class TakeoverSignature:
    service: str
    cname_suffixes: Tuple[str, ...]
    body_markers: Tuple[str, ...]
    status_codes: Tuple[int, ...] = (404,)

TAKEOVER_SIGNATURES: Tuple[TakeoverSignature, ...] = (
    TakeoverSignature(
        service="Heroku",
        cname_suffixes=(".herokuapp.com", ".herokudns.com"),
        body_markers=("no such app", "there is no app configured at that hostname"),
        status_codes=(404, 502, 503),
    ),
    TakeoverSignature(
        service="GitHub Pages",
        cname_suffixes=(".github.io",),
        body_markers=("there isn't a github pages site here",),
        status_codes=(404,),
    ),
    # CORRECTION EXPERT : Restriction aux endpoints S3 Website uniquement
    TakeoverSignature(
        service="AWS S3 (Website)",
        cname_suffixes=(
            ".s3-website-", 
            ".s3-website.", 
            # On retire .amazonaws.com pour éviter les FP sur ELB/CloudFront/EC2
        ),
        body_markers=("the specified bucket does not exist", "no such bucket"),
        status_codes=(404,),
    ),
    TakeoverSignature(
        service="Azure (Web App / Front Door)",
        cname_suffixes=(".azurewebsites.net", ".trafficmanager.net", ".azurefd.net"),
        body_markers=("404 web site not found", "the resource you are looking for has been removed"),
        status_codes=(404,),
    ),
    TakeoverSignature(
        service="Pantheon",
        cname_suffixes=(".pantheonsite.io",),
        body_markers=("the gods are wise", "but do not know of the site which you seek"),
        status_codes=(404,),
    ),
    TakeoverSignature(
        service="Tumblr",
        cname_suffixes=(".tumblr.com",),
        body_markers=("whatever you were looking for doesn't currently exist at this address",),
        status_codes=(404,),
    ),
    TakeoverSignature(
        service="Shopify",
        cname_suffixes=(".myshopify.com",),
        body_markers=("sorry, this shop is currently unavailable",),
        status_codes=(404,),
    ),
    TakeoverSignature(
        service="Zendesk",
        cname_suffixes=(".zendesk.com",),
        body_markers=("help center closed",),
        status_codes=(404,),
    ),
)

def match_takeover_signature(cname: str) -> Optional[TakeoverSignature]:
    if not cname:
        return None
    
    # Normalisation du CNAME candidat
    c = cname.strip().lower().rstrip(".") 
    
    for sig in TAKEOVER_SIGNATURES:
        for suf in sig.cname_suffixes:
            # Normalisation du suffixe de référence
            s = suf.lower().strip(".")
            
            # Matching strict de frontière DNS
            if c == s or c.endswith("." + s):
                return sig
    return None

def body_contains_marker(body: str, markers: Iterable[str]) -> bool:
    b = (body or "").lower()
    return any(m.lower() in b for m in markers)