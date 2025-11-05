import faiss, numpy as np
from sentence_transformers import SentenceTransformer

class EmbeddingIndex:
    def __init__(self, model_name="all-MiniLM-L6-v2"):
        self.model = SentenceTransformer(model_name)
        self.dim = self.model.get_sentence_embedding_dimension()
        self.index = faiss.IndexFlatIP(self.dim)
        self.docs = []

    def add_docs(self, docs):
        texts = [d["text"] for d in docs]
        ids = [d["id"] for d in docs]
        vecs = self.model.encode(texts, convert_to_numpy=True).astype("float32")
        faiss.normalize_L2(vecs)
        self.index.add(vecs)
        self.docs.extend(docs)
        self.ids = ids

    def retrieve(self, query, k=3):
        qv = self.model.encode([query], convert_to_numpy=True).astype("float32")
        faiss.normalize_L2(qv)
        D, I = self.index.search(qv, k)
        return [self.docs[i]["text"] for i in I[0]]
