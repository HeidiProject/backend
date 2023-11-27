import uuid

from loguru import logger

import mxdbclient

try:
    mxdb = mxdbclient.mxdbclient()
except Exception as e:
    logger.info(f"Exception: {e}. Unable to connect to mongo database.")


def get_user(user_account, api_key):
    """
    Get the UUID4 token from MongoDB for the user account.

    Returns:
        Str: pgroup/invalid
    """
    documents = mxdb.query(
        collection="Users", _id=user_account, key=api_key, qtype="find_one"
    )
    return documents


def get_token(token_id):
    """
    Get the UUID4 API token from MongoDB to confirm it is valid.

    Returns:
        Str: pgroup/invalid
    """
    document = mxdb.query(collection="Tokens", token_id=token_id, qtype="find_one")
    if document["status"] == "active":
        return document["pgroup"]
    return None


def get_tokens(pgroup):
    """
    Get the UUID4 API tokens from MongoDB for a selected pgroup.

    Returns:
        Array:[
            {
                "_id": "64cbbf8aac7205ed0716cffc",
                "pgroup": "p18482",
                "token_id": "d01da8f7-29bd-4a1b-bd9c-a627a9f0af12"
            },
        ]
    """
    kwargs = {}
    kwargs["pgroup"] = pgroup
    kwargs["status"] = "active"
    documents = mxdb.query(collection="Tokens", **kwargs)
    return documents


def create_token(**kwargs):
    """
    Put the UUID4 API token into MongoDB.

    Returns:
       dict: {"insertID":"64ccad71ac7205ed0716d007","status":"OK"}
    """
    kwargs["token_id"] = generate_api_token()
    kwargs["status"] = "active"
    document = mxdb.insert(collection="Tokens", **kwargs)
    return document


def delete_token(token):
    """
    Revoke the UUID4 API token in MongoDB

    Returns:
        dict: {"matched_count":1,"modified_count":1,"status":"OK","upserted_id":null}
    """
    logger.info(f"token for deletion is {token}")
    document = mxdb.update(
        collection="Tokens", query={"_id": token}, update={"status": "revoked"}
    )
    return document


def generate_api_token():
    """
    Generate a UUID4 API token for use to programmatically access endpoints.

    Returns:
        str: UUID4 token as a string.
    """
    return str(uuid.uuid4())


def adp_get_results(user_account, after=None, before=None):
    """
    Query the Adp and Datasets collection for experiment information.

    Returns:
        Array of JSON objects
    """
    if not (after or before):
        documents = mxdb.query(collection="Adp", userAccount=user_account)
    else:
        documents = mxdb.query(
            collection="Adp",
            userAccount=user_account,
            after=after,
            before=before,
            sortkey="createdOn",
        )
    # Refactor in smarter way with database lookups
    if len(documents) > 0:
        for index, document in enumerate(documents):
            dataset = mxdb.query(
                qtype="aggregate",
                collection=f"""Datasets&match={{'trackingId':'{document['trackingId']}'}}&
                                 project={{'metadata':1,'wedges':1}}""",
            )
            if "metadata" in dataset[0].keys():
                for item in dataset[0]["metadata"]:
                    if item["name"] == "beamlineFluxAtSample":
                        document["beamlineFluxAtSample"] = item["value"]
                    elif item["name"] == "beamSizeWidth":
                        document["beamSizeWidth"] = item["value"]
                    elif item["name"] == "beamSizeHeight":
                        document["beamSizeHeight"] = item["value"]
                    if item["name"] == "aperture":
                        document["aperture"] = item["value"]
                if not document["aperture"]:
                    document["aperture"] = "no aperture"
            if "wedges" in dataset[0].keys():
                for item in dataset[0]["wedges"]:
                    if "chi" in item.keys():
                        document["chi"] = item["chi"]
                    if "phi" in item.keys():
                        document["phi"] = item["phi"]
    return documents


def vespa_get_results(user_account):
    """
    Query the Vdp collection for SSX processing information

    Returns:
        Array: [
            {
                '_id': '6511241e540c74f790949ab7',
                'mergeID': 'lyso',
                'dataFileName': 'Lyso_run000026_data_000010.h5',
                'numberOfImages': 10000,
                'crystfelTreshold': 5.0,
                'crystfelMinSNR': 3.0,
                'crystfelMinPixCount': 1,
                'numberOfImagesIndexed': 1432,
                'createdOn': '2023-09-21T08:09:34.357000+00:00'
            }
        ]
    """
    documents = mxdb.query(
        qtype="aggregate",
        collection=f"""Vdp&match={{'eaccount':'{user_account}'}}&
                    project={{'crystfelMinPixCount':1,'crystfelMinSNR':1,'crystfelTreshold':1,
                    'numberOfImages':1,'numberOfImagesIndexed':1,'mergeID':1,'dataFileName':1,
                    'createdOn':1}}&sort={{'createdOn':-1}}"""
        # For graphing spots per image add this: {'numberOfSpotsPerImage':1}
    )
    return documents


if __name__ == "__main__":
    vespa_get_results("e19370")
