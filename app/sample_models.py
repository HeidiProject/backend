"""
Data model and validation for mandatory and single sample rows from
spreadsheet. Can be imported by sample_importer.py and database services.
"""

import re
from typing import Any, Optional, Union

from pydantic import BaseModel, Field, validator

from typing_extensions import Annotated


class SpreadsheetModel(BaseModel):
    dewarname: str
    puckname: str
    pucktype: Optional[str] = "unipuck"
    pucklocationindewar: Optional[Union[int, str]]
    crystalname: Annotated[
        str,
        Field(
            max_length=64,
            title="Crystal Name",
            description="""max_length imposed by MTZ file header format
                        https://www.ccp4.ac.uk/html/mtzformat.html""",
        ),
    ]
    positioninpuck: int
    priority: Optional[str]
    comments: Optional[str]
    pinbarcode: Optional[str]
    directory: Optional[str]
    proteinname: Any = ""
    oscillation: Any = ""
    exposure: Any = ""
    totalrange: Any = ""
    transmission: Any = ""
    targetresolution: Any = ""
    aperture: Any = ""
    datacollectiontype: Any = ""
    processingpipeline: Any = ""
    spacegroupnumber: Any = ""
    cellparameters: Any = ""
    rescutkey: Any = ""
    rescutvalue: Any = ""
    userresolution: Any = ""
    pdbmodel: Any = ""
    autoprocfull: Any = ""
    procfull: Any = ""
    adpenabled: Any = ""
    noano: Any = ""
    trustedhigh: Any = ""
    ffcscampaign: Any = ""
    autoprocextraparams: Any = ""
    chiphiangles: Any = ""

    @validator("dewarname", "puckname")
    def dewarname_puckname_characters(cls, v, **kwargs):
        assert (
            len(str(v)) > 0
        ), f"""" {v} " is not valid.
            value must be provided for all samples in spreadsheet."""
        v = str(v).replace(" ", "_")
        if re.search("\n", v):
            assert v.isalnum(), "is not valid. newline character detected."
        v = re.sub(r"\.0$", "", v)
        return v.upper()

    @validator("crystalname")
    def parameter_characters(cls, v, **kwargs):
        v = str(v).replace(" ", "_")
        if re.search("\n", v):
            assert v.isalnum(), "is not valid. newline character detected."
        characters = re.sub("[._+-]", "", v)
        assert characters.isalnum(), f"""" {v} " is not valid.
            must contain only alphanumeric and . _ + - characters"""
        v = re.sub(r"\.0$", "", v)
        return v

    @validator("directory")
    def directory_characters(cls, v, **kwargs):
        if v:
            v = str(v).strip("/").replace(" ", "_")
            if re.search("\n", v):
                raise ValueError(
                    f"""" {v} " is not valid.
                                 newline character detected."""
                )
            ok = "[a-z0-9_.+-]"
            directory_re = re.compile("^((%s*|{%s+})*/?)*$" % (ok, ok), re.IGNORECASE)
            if not directory_re.match(v):
                raise ValueError(
                    f"' {v} ' is not valid. value must be a path or macro."
                )

            these_macros = re.findall(r"(\{[^}]+\})", v)
            valid_macros = [
                "{date}",
                "{prefix}",
                "{sgpuck}",
                "{puck}",
                "{beamline}",
                "{sgprefix}",
                "{sgpriority}",
                "{sgposition}",
                "{protein}",
                "{method}",
            ]
            for m in these_macros:
                if m.lower() not in valid_macros:
                    raise ValueError(
                        f"""" {m} " is not a valid macro, please re-check documentation;
                        allowed macros: date, prefix, sgpuck, puck, beamline, sgprefix,
                        sgpriority, sgposition, protein, method"""
                    )
        return v

    @validator("positioninpuck", pre=True)
    def positioninpuck_possible(cls, v, **kwargs):
        if v:
            try:
                v = int(float(v))
                if v < 1 or v > 16:
                    raise ValueError(
                        f"""" {v} " is not valid. value must be from 1 to 16."""
                    )
            except (ValueError, TypeError) as e:
                raise ValueError(
                    f"""" {v} " is not valid.
                    Value must be a numeric type and from 1 to 16."""
                ) from e
        else:
            raise ValueError("Value must be provided. Value must be from 1 to 16.")
        return v

    @validator("pucklocationindewar")
    def pucklocationindewar_convert_to_int(cls, v, **kwargs):
        return int(float(v)) if v else v

    @validator("priority")
    def priority_positive(cls, v, **kwargs):
        if v:
            v = re.sub(r"\.0$", "", v)
            try:
                if not int(v) > 0:
                    raise ValueError(
                        f"""" {v} " is not valid.
                        value must be a positive integer."""
                    )
                elif int(v) > 0:
                    v = int(v)
            except (ValueError, TypeError) as e:
                raise ValueError(
                    f"""" {v} " is not valid.
                    value must be a positive integer."""
                ) from e
        return v

    @validator("aperture")
    def aperture_selection(cls, v, **kwargs):
        if v:
            try:
                v = int(float(v))
                if v not in [1, 2, 3]:
                    raise ValueError(
                        f"""" {v} " is not valid.
                        value must be integer 1, 2 or 3."""
                    )
            except (ValueError, TypeError) as e:
                raise ValueError(
                    f"""" {v} " is not valid.
                    value must be integer 1, 2 or 3."""
                ) from e
        return v

    @validator(
        "oscillation",
        "exposure",
        "totalrange",
        "targetresolution",
        "rescutvalue",
        "userresolution",
    )
    def parameter_positive_float(cls, v, **kwargs):
        if v:
            try:
                v = float(v)
                if not v > 0:
                    raise ValueError(
                        f"""" {v} " is not valid.
                        value must be a positive float."""
                    )
            except (ValueError, TypeError) as e:
                raise ValueError(
                    f"""" {v} " is not valid.
                    value must be a positive float."""
                ) from e
        return v

    @validator("transmission")
    def tranmission_fraction(cls, v, **kwargs):
        if v:
            try:
                v = float(v)
                if 100 >= v > 0:
                    v = v
                else:
                    raise ValueError(
                        f"""" {v} " is not valid.
                        value must be a float between 0 and 100."""
                    )
            except (ValueError, TypeError) as e:
                raise ValueError(
                    f"""" {v} " is not valid.
                    value must be a float between 0 and 100."""
                ) from e
        return v

    @validator("datacollectiontype")
    def datacollectiontype_allowed(cls, v, **kwargs):
        if v:
            v = v.lower()
            allowed = ["standard", "serial-xtal", "multi-orientation"]
            if str(v) not in allowed:
                raise ValueError(
                    f"""" {v} " is not valid.
                                 value must be one of" {allowed} "."""
                )
        return v

    @validator("processingpipeline")
    def processingpipeline_allowed(cls, v, **kwargs):
        if v:
            v = v.lower()
            allowed = ["gopy", "autoproc", "xia2dials"]
            if str(v) not in allowed:
                raise ValueError(
                    f"""" {v} " is not valid.
                                 value must be one of " {allowed} "."""
                )
        return v

    @validator("spacegroupnumber")
    def spacegroupnumber_integer(cls, v, **kwargs):
        if v:
            try:
                v = int(float(v))
                if not v > 0 or not v < 231:
                    raise ValueError(
                        f"""" {v} " is not valid.
                        value must be a positive integer between 1 and 230."""
                    )
            except (ValueError, TypeError) as e:
                raise ValueError(
                    f"""" {v} " is not valid.
                    value must be a positive integer between 1 and 230."""
                ) from e
        return v

    @validator("cellparameters")
    def cellparameters_positive_floats(cls, v, **kwargs):
        if v:
            splitted = str(v).split(" ")
            if len(splitted) != 6:
                raise ValueError(
                    f"' {v} ' is not valid. value must be a set of six numbers."
                )
            for el in splitted:
                try:
                    el = float(el)
                    if not el > 0:
                        raise ValueError(
                            f"' {el} ' is not valid. value must be a positive float."
                        )
                except (ValueError, TypeError) as e:
                    raise ValueError(
                        f"' {el} ' is not valid. value must be a positive float."
                    ) from e
        return v

    @validator("rescutkey")
    def rescutkey_allowed(cls, v, **kwargs):
        if v:
            v = v.lower()
            allowed = ["is", "cchalf"]
            if str(v) not in allowed:
                raise ValueError(f"' {v} ' is not valid. value must be ' {allowed} '.")
        return v

    @validator("autoprocfull", "procfull", "adpenabled", "noano", "ffcscampaign")
    def boolean_allowed(cls, v, **kwargs):
        if v:
            v = v.title()
            allowed = ["False", "True"]
            if str(v) not in allowed:
                raise ValueError(
                    f"""" {v} " is not valid.
                                 value must be ' {allowed} '."""
                )
        return v

    @validator("trustedhigh")
    def trusted_float(cls, v, **kwargs):
        if v:
            try:
                v = float(v)
                if 2.0 >= v > 0:
                    v = v
                else:
                    raise ValueError(
                        f"""" {v} " is not valid.
                        value must be a float between 0 and 2.0."""
                    )
            except (ValueError, TypeError) as e:
                raise ValueError(
                    f"""" {v} " is not valid.
                    value must be a float between 0 and 2.0."""
                ) from e
        return v

    @validator("proteinname")
    def proteinname_characters(cls, v, **kwargs):
        if v:
            v = str(v).replace(" ", "_")
            if re.search("\n", v):
                assert v.isalnum(), "is not valid. newline character detected."
            characters = re.sub("[._+-]", "", v)
            assert characters.isalnum(), f"""" {v} " is not valid.
                must contain only alphanumeric and . _ + - characters"""
            v = re.sub(r"\.0$", "", v)
        return v

    @validator("chiphiangles")
    def chiphiangles_value(cls, v, **kwargs):
        if v:
            try:
                v = str(v)
                re.sub(r"(^\s*\[\s*|\s*\]\s*$)", "", v.strip())
                list_of_strings = re.findall(r"\(.*?\)", v)
                list_of_tuples = []
                for el in list_of_strings:
                    first = re.findall(r"\(.*?\,", el)[0].replace(" ", "")[1:-1]
                    second = re.findall(r"\,.*?\)", el)[0].replace(" ", "")[1:-1]
                    my_tuple = (float(first), float(second))
                    list_of_tuples.append(my_tuple)
                v = list_of_tuples
            except (ValueError, TypeError) as e:
                raise ValueError(
                    f"""" {v} " is not valid. Example format is
                    (0.0, 0.0), (20.0, 0.0), (30, 0.0)"""
                ) from e
        return v

    @validator(
        "priority",
        "comments",
        "pinbarcode",
        "directory",
        "proteinname",
        "oscillation",
        "exposure",
        "totalrange",
        "transmission",
        "targetresolution",
        "aperture",
        "datacollectiontype",
        "processingpipeline",
        "spacegroupnumber",
        "cellparameters",
        "rescutkey",
        "rescutvalue",
        "userresolution",
        "pdbmodel",
        "autoprocfull",
        "procfull",
        "adpenabled",
        "noano",
        "trustedhigh",
        "ffcscampaign",
        "autoprocextraparams",
        "chiphiangles",
    )
    def set_default_emptystring(cls, v, **kwargs):
        return v or ""

    class Config:
        anystr_strip_whitespace = True


class TELLModel(SpreadsheetModel):
    input_order: int
    samplemountcount: int = 0
    samplestatus: str = "not present"
    puckaddress: str = "---"
    username: str
    puck_number: int
    prefix: Optional[str]
    folder: Optional[str]


"""
Following params appended in teller.py for updating SDU sample model
class SDUTELLModel(TELLModel):
    sdudaq: str
    sdudiffcenter: str
    sduopticalcenter: str
    sdumount: str
    sdusafetycheck: str

Following params returned in the format expected by tell.set_samples_info()
{
    "userName": user,
    "dewarName": sample["dewarname"],
    "puckName": "",  # FIXME at the moment this field is useless
    "puckType": "Unipuck",
    "puckAddress": sample["puckaddress"],
    "puckBarcode": sample["puckname"],
    "sampleBarcode": sample.get("pinbarcode", ""),
    "sampleMountCount": sample["samplemountcount"],
    "sampleName": sample["crystalname"],
    "samplePosition": sample["positioninpuck"],
    "sampleStatus": sample["samplestatus"],
}
"""
