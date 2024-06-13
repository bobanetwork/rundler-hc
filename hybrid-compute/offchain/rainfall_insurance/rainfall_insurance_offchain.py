import os
from dotenv import load_dotenv
from web3 import Web3
import requests
from eth_abi import abi as ethabi
from offchain_utils import gen_response, parse_req

load_dotenv()

# For weather-api
API_KEY = ""


def offchain_getrainfall(sk, src_addr, src_nonce, oo_nonce, payload, *args):
    print("  -> offchain_getrainfall handler called with subkey={} src_addr={} src_nonce={} oo_nonce={} payload={} extra_args={}".format(sk,
          src_addr, src_nonce, oo_nonce, payload, args))
    err_code = 0
    resp = Web3.to_bytes(text="unknown error")

    try:
        req = parse_req(sk, src_addr, src_nonce, oo_nonce, payload)
        dec = ethabi.decode(['string'], req['reqBytes'])
        city = dec[0]
        print("city", city)

        weather_url = "https://api.weatherapi.com/v1/current.json?q={}&key={}".format(
            city, API_KEY)
        headers = {
            "accept": "application/json",
        }
        print('weather_url', weather_url)

        weather_response = requests.get(weather_url, headers=headers)

        print('weatherResponse', weather_response)

        rainfall = None

        if weather_response.status_code == requests.codes.ok:
            weather_data = weather_response.json()
            rainfall = weather_data['current']['precip_mm']
            scaled_rainfall = int(rainfall * 100)
            print("Rainfall for {}: ".format(city), rainfall)
            resp = ethabi.encode(["uint256"], [scaled_rainfall])
            err_code = 0
        else:
            print("Error:", weather_response.status_code, weather_response.text)
            err_code = 1
            resp = Web3.to_bytes(
                text="Error: {}".format(weather_response.status_code))

    except Exception as e:
        print("DECODE FAILED", e)

    return gen_response(req, err_code, resp)


