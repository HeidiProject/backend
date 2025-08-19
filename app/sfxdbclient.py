import requests
from typing import Any, Dict, List

class SFXDBClient:
    def __init__(self, base_url: str = "https://_add_url_here:8008"):
        self.base_url = base_url
        self.session = requests.Session()

    def get_experiment_data(self, experiment_group: str = "") -> List[Dict[str, Any]]:
        """
        Fetches experiment data from the FastAPI server.

        Parameters:
            experiment_group (str): The experiment group ID to filter data. Defaults to "".

        Returns:
            List[Dict[str, Any]]: The JSON response as a list of dictionaries.
        """
        url = f"{self.base_url}/experiment-data/"
        params = {"experiment_group": experiment_group}
        
        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred: {http_err}")
        except requests.exceptions.RequestException as req_err:
            print(f"Error occurred during the request: {req_err}")
        
        return []


    def get_experiment_data_summary(self, experiment_group: str = "") -> List[Dict[str, Any]]:
        """
        Fetches experiment data from the FastAPI server.

        Parameters:
            experiment_group (str): The experiment group ID to filter data. Defaults to "".

        Returns:
            List[Dict[str, Any]]: The JSON response as a list of dictionaries.
        """
        url = f"{self.base_url}/experiment-data-summary/"
        params = {"experiment_group": experiment_group}
        
        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred: {http_err}")
        except requests.exceptions.RequestException as req_err:
            print(f"Error occurred during the request: {req_err}")
        
        return []
    

    def get_ffcs_campaigns(self, user_account: str = "") -> List[Dict[str, Any]]:
        """
        Fetches experiment data from the FastAPI server.

        Parameters:
            experiment_group (str): The experiment group ID to filter data. Defaults to "p21981".

        Returns:
            List[Dict[str, Any]]: The JSON response as a list of dictionaries.
        """
        url = f"{self.base_url}/ffcs-summary/"
        params = {"user_account": user_account}
        
        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred: {http_err}")
        except requests.exceptions.RequestException as req_err:
            print(f"Error occurred during the request: {req_err}")
        
        return []
    

    def get_ffcs_campaign_data_summary(self, user_account: str = "", campaign_id: str = "") -> List[Dict[str, Any]]:
        """
        Fetches experiment data from the FastAPI server.

        Parameters:
            experiment_group (str): The experiment group ID to filter data. Defaults to "p21981".

        Returns:
            List[Dict[str, Any]]: The JSON response as a list of dictionaries.
        """
        url = f"{self.base_url}/ffcs-campaign-summary/"
        params = {"user_account": user_account, "campaign_id": campaign_id}
        
        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred: {http_err}")
        except requests.exceptions.RequestException as req_err:
            print(f"Error occurred during the request: {req_err}")
        
        return []


    def close(self):
        """Closes the client session."""
        self.session.close()
