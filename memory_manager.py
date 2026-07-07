import os
import chromadb
from chromadb.utils import embedding_functions
from dotenv import load_dotenv

load_dotenv()

class MemoryManager:
    def __init__(self, db_path="./chroma_db"):
        """Initialise ChromaDB for storing past analyses"""
        self.client = chromadb.PersistentClient(path=db_path)
        self.embed_fn = embedding_functions.OpenAIEmbeddingFunction(
            api_key=os.getenv("OPENAI_API_KEY"),
            model_name="text-embedding-3-small"
        )
        self.collection = self.client.get_or_create_collection(
            name="fra_memory",
            embedding_function=self.embed_fn
        )
        print(f"Memory Manager ready. Stored cases: {self.collection.count()}")

    def store(self, pcap_name, flow_summary, report):
        """Store a completed analysis in memory"""
        try:
            # Use pcap filename as unique ID
            doc_id = pcap_name.replace(".pcap", "").replace("/", "_").replace("\\", "_")

            document = f"""PCAP: {pcap_name}
FLOW SUMMARY:
{flow_summary[:500]}

REPORT:
{report[:1000]}
"""
            self.collection.upsert(
                ids=[doc_id],
                documents=[document],
                metadatas=[{"pcap": pcap_name, "type": "forensic_analysis"}]
            )
            #print(f"Stored analysis for: {pcap_name}")
        except Exception as e:
            print(f"Error storing memory: {e}")

    def retrieve(self, flow_summary, n_results=2):
        """Retrieve similar past analyses"""
        try:
            if self.collection.count() == 0:
                return "No past cases found in memory."

            results = self.collection.query(
                query_texts=[flow_summary[:500]],
                n_results=min(n_results, self.collection.count())
            )

            if not results["documents"][0]:
                return "No similar cases found."

            past_cases = ""
            for i, doc in enumerate(results["documents"][0]):
                past_cases += f"\n--- Past Case {i+1} ---\n{doc[:600]}\n"

            return past_cases
        except Exception as e:
            return f"Error retrieving memory: {e}"

    def count(self):
        """Return number of stored cases"""
        return self.collection.count()