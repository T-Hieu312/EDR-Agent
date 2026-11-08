from edr.client import EDRClient


if __name__ == "__main__":
    client = EDRClient(server_url="http://127.0.0.1:8000")
    result = client.run_once()
    print(result)
