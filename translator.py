import chromadb
# This creates a local database to store vendor manuals
client = chromadb.Client()
collection = client.create_collection("network_manuals")
# The SLM will search this collection to translate messy code into JSON