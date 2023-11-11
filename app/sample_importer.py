import copy
import getpass
import re
from typing import List

from loguru import logger

from pydantic import ValidationError, parse_obj_as

from sample_models import SpreadsheetModel, TELLModel

import xlrd
from xlrd import XLRDError


UNASSIGNED_PUCKADDRESS = "---"
user = getpass.getuser()


class SpreadsheetImportError(Exception):
    pass


class SampleSpreadsheetImporter(object):
    def __init__(self, quiet=False, **kwargs):
        self._quiet = quiet
        self._filename = None
        self.model = None
        self.barcodes = []
        self.validator_app = False
        self.available_puck_positions = []

    def import_spreadsheet(self, filename, as_data_blob=False, validator_app=False):
        """
        Imports spreadsheet in xls format.
        If as_data_blob=False -> filename is path to .xls file on disk
        If as_data_blob=True, filename contains binary data structure of
        already read .xls file
        """
        self.available_puck_positions = [
            f"{s}{p}" for s in list("ABCDEF") for p in range(1, 6)
        ]
        self.available_puck_positions.append(UNASSIGNED_PUCKADDRESS)
        self.validator_app = validator_app
        self._filename = filename

        try:
            if not as_data_blob:  # Read .xls file from disk
                logger.info(f"Importing spreadsheet from .xls_file: {filename}")
                book = xlrd.open_workbook(filename)
            else:
                logger.info("Importing spreadsheet in .xls format from data blob")
                book = xlrd.open_workbook(file_contents=filename.read())
        except XLRDError as e:
            raise SpreadsheetImportError(e.args[0])

        try:
            sheet = book.sheet_by_name("Samples")
        except XLRDError as e:
            logger.info(f"XLRDError exception: {e}.")
            try:
                sheet = book.sheet_by_index(0)
            except XLRDError as e:
                raise SpreadsheetImportError(
                    """excel file is missing 'Samples' worksheet;
                    samples must be listed in a worksheet named 'Samples'"""
                ) from e

        return self.process_spreadsheet(sheet)

    def process_spreadsheet(self, sheet):
        model = []
        headers = None

        for row, contents in enumerate(sheet.get_rows()):
            reduced = [
                str(c.value).lower().replace(" ", "").replace("*", "") for c in contents
            ]
            if "dewarname" in reduced:
                headers = reduced
                start_row = 1 + row
                break

        if headers is None:
            raise SpreadsheetImportError("The dewarname column is missing.")

        # remove typehints [str], [int], [bool], etc. from header column
        for n, key in enumerate(headers):
            key = re.sub(r"\[.*\]", "", "".join(key.split()))
            headers[n] = key

        class SkipRow(Exception):
            pass

        logger.info(sheet)
        logger.info(sheet.nrows)
        for row in range(start_row, sheet.nrows):
            values = sheet.row_values(row)
            sample = {}
            count = 0
            for i, j in enumerate(values):
                if len(str(j)) > 0:
                    count += 1

            # if there are no values in any of the cells skip row
            if count == 0:
                continue

            try:
                for key in headers:
                    val = values[headers.index(key)]
                    val = str(val).strip()
                    sample[key] = val

            except SkipRow as e:
                logger.warning(e)
                continue

            model.append(sample)

        logger.info(f"...finished import, got {len(model)} samples")

        self.model = model

        try:
            model = self.validate()
            if self.validator_app:
                model = sorted(
                    model,
                    key=lambda k: (k["puckname"], int(k["positioninpuck"])),
                    reverse=False,
                )
        except SpreadsheetImportError as e:
            logger.error(f"Error: {e}. failed to import spreadsheet: {self._filename}")
            raise

        # TELL fields for the already validated data model
        if not self.validator_app:
            barcodes = {}
            pnum = 0

            for sample in model:
                sample_number = 1
                puck_address = UNASSIGNED_PUCKADDRESS
                if sample["puckname"] not in barcodes:
                    try:
                        simu_puckaddress = self.available_puck_positions.pop(0)
                    except Exception as e:
                        logger.info(f"Exception: {e}. Puck unassigned.")
                        simu_puckaddress = UNASSIGNED_PUCKADDRESS
                barcodes[sample["puckname"]] = (pnum, simu_puckaddress)
                pnum += 1
                sample.update(
                    {
                        "input_order": sample_number,
                        "samplemountcount": 0,
                        "samplestatus": "not present",
                        "puckaddress": puck_address,
                        "username": user,
                        "puck_number": barcodes[sample["puckname"]][0],
                        "prefix": sample["crystalname"],
                        "folder": sample["directory"],
                    }
                )
                sample_number += 1
            print(model[-1])
            keys = list(barcodes.keys())
            self.barcodes = copy.copy(keys)

            # 1. data model validation of TELL sample entries
            model = self.data_model_validation(TELLModel, model)

            logger.info(f"...finished TELL import, got {len(model)} samples")

        logger.info(f"...finished validation, got {len(model)} samples")

        return model

    def validate(self):
        """go over imported spreadsheet and sanitizes and validate the data
        1. data model validation of single sample entries
        2 validate unique puck names with puck capacity (maximum of 16 samples)
        3. validate unique puck positions (1-16)
        """

        model = self.model
        logger.info(f"...validating {len(model)} samples")

        # 1. data model validation of single sample entries
        validated_model = self.data_model_validation(SpreadsheetModel, model)

        pucks = set([s["puckname"] for s in validated_model])
        for puck in pucks:
            number_of_pins = len([s for s in validated_model if puck == s["puckname"]])
            pin_numbers = [
                s["positioninpuck"] for s in validated_model if puck == s["puckname"]
            ]
            # 2 validate unique puck names with puck capacity (maximum of 16 samples)
            if number_of_pins > 16:
                raise SpreadsheetImportError(
                    f"""repeated puckname for puck named " {puck.upper()} ":
                    contains {number_of_pins} pins."""
                )
            # 3. validate unique puck positions (1-16)
            elif number_of_pins != len(set(pin_numbers)):
                raise SpreadsheetImportError(
                    f"""repeated positioninpuck for puck named
                    " {puck.upper()} ": {pin_numbers}. """
                )
        return validated_model

    @staticmethod
    def data_model_validation(data_model, model):
        try:
            validated = parse_obj_as(List[data_model], model)
        except ValidationError as e:
            raise SpreadsheetImportError(
                f"{e.errors()[0]['loc'][2]} => {e.errors()[0]['msg']}"
            )
        validated_model = []
        for index, value in enumerate(validated):
            validated_model.append(dict(value))
        return validated_model


def main():
    parser = argparse.ArgumentParser(
        description="Sample spreadsheet importer & validator"
    )
    parser.add_argument("files", nargs="+", help="list of files to import")
    parser.add_argument(
        "-q",
        "--quiet",
        help="do not print anything just exit with 0=file ok 1=file not ok",
        action="store_true",
    )
    parser.add_argument(
        "-j",
        "--json",
        help="dump a JSON version of the spreadsheet",
        action="store_true",
    )
    args = parser.parse_args()

    if args.quiet:
        logger.remove()
        logger.add(sink=sys.stdout, level="CRITICAL")

    importer = SampleSpreadsheetImporter()
    for file in args.files:
        model = None
        try:
            model = importer.import_spreadsheet(file, validator_app=False)
        except SpreadsheetImportError as e:
            if args.quiet:
                sys.exit(1)
            logger.error(e)
        if args.json:
            import json

            print(json.dumps(model, indent=4))


if __name__ == "__main__":
    import sys
    import argparse

    main()
    sys.exit(0)
