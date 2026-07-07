from llm_client import get_llm

llm = get_llm("gpt")

response = llm.invoke("Say only: OpenRouter is working")

print(response.content)