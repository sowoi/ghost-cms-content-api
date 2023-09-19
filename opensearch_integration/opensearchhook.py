!.venv/bin/python3

import subprocess
import os
import argparse
import asyncio
from flask import Flask, request, jsonify
from opensearchpy import OpenSearch
from opensearchpy.connection import create_ssl_context
import requests
import warnings
from urllib3.exceptions import InsecureRequestWarning

app = Flask(__name__)

warnings.simplefilter('ignore', InsecureRequestWarning)


ssl_context = create_ssl_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = False


def get_config():
    parser = argparse.ArgumentParser(description="Konfigurationsargumente für das Skript")
    
    # Argumente für Ghost
    parser.add_argument('--ghost_api_url', default=os.environ.get('GHOST_API_URL'))
    parser.add_argument('--ghost_api_key', default=os.environ.get('GHOST_API_KEY'))
    
    # Argumente für OpenSearch
    parser.add_argument('--opensearch_host', default=os.environ.get('OPENSEARCH_HOST', 'https://localhost:9444'))
    parser.add_argument('--opensearch_index', default=os.environ.get('OPENSEARCH_INDEX_NAME'))
    parser.add_argument('--opensearch_username', default=os.environ.get('OPENSEARCH_USERNAME'))
    parser.add_argument('--opensearch_password', default=os.environ.get('OPENSEARCH_PASSWORD'))

    args = parser.parse_args()

    return args


def fetch_ghost_posts():
    print("trying ghost")
    response = requests.get(f"{GHOST_API_URL}/posts/?key={GHOST_API_KEY}&limit=all&fields=id,title,slug,url,excerpt,content,html&include=tags")
    if response.status_code == 200:
        return response.json()["posts"]
    else:
        print("ghost failed")
        response.raise_for_status()

def send_to_opensearch(posts):
    client = OpenSearch(
      [OPENSEARCH_HOST],
        http_auth=(OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD),
        verify_certs=False
    )

    # Clear previous data (be cautious with this in a production environment)
    if client.indices.exists(index=OPENSEARCH_INDEX_NAME):
      client.indices.delete(index=OPENSEARCH_INDEX_NAME)
      client.indices.create(index=OPENSEARCH_INDEX_NAME)
    else:
       print(f"Index {OPENSEARCH_INDEX_NAME} doesn't exist.")
       client.indices.create(index=OPENSEARCH_INDEX_NAME)

    for post in posts:
       client.index(index=OPENSEARCH_INDEX_NAME, body=post)
        

@app.route('/buildindex', methods=['POST'])
def index_data():
    client_ip = request.remote_addr
    print(f"Request received from IP: {client_ip}")
    if client_ip == "127.0.0.1":
        try:
            posts = fetch_ghost_posts()
            send_to_opensearch(posts)
            print(f"Sent {len(posts)} posts to OpenSearch.")
            return jsonify({"message": "index executed successfully"}), 200
        except Exception as e:
            print(f"Error executing index: {e}")
            return jsonify({"error": "Failed to execute index"}), 500
    else:
        abort(403)


@app.route('/search', methods=['POST'])
async def search():
    os_client = OpenSearch(
        hosts=[OPENSEARCH_HOST],
        http_auth=(OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD),
        verify_certs=False,
        ssl_context=ssl_context
    )

    data = request.json
    print(data)
    if 'query' not in data:
        print("Query not provided")
        return jsonify({"error": "Query not provided"}), 400

    query = data['query']
    print(query)
    body = {
        "query": {
            "multi_match": {
                "query": query,
                "fields": ["title", "html", "slug", "url", "excerpt", "content", "tags.name", "authors", "published_at", "id"]
            }
        }
    }
    print(body)

    loop = asyncio.get_event_loop()

    try:
        response = await loop.run_in_executor(None, lambda: os_client.search(index=OPENSEARCH_INDEX_NAME, body=body))
        hits = response['hits']['hits']

        seen_ids = set()
        unique_results = []

        for hit in hits:
            doc_id = hit["_source"]["id"]
            if doc_id not in seen_ids:
                seen_ids.add(doc_id)
                unique_results.append(hit["_source"])

        print(unique_results)
        return jsonify(unique_results)

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": "Search failed"}), 500


if __name__ == "__main__":
    config = get_config()

    GHOST_API_URL = config.ghost_api_url
    GHOST_API_KEY = config.ghost_api_key
    OPENSEARCH_HOST = config.opensearch_host
    OPENSEARCH_INDEX_NAME = config.opensearch_index
    OPENSEARCH_USERNAME = config.opensearch_username
    OPENSEARCH_PASSWORD = config.opensearch_password

    app.run(port=3444, debug=True)
