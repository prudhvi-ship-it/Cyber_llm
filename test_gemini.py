from llm_client import get_llm

#llm = get_llm("google/gemini-flash-1.5")
llm = get_llm("google/gemini-2.5-flash")
response = llm.invoke("Say only: Gemini reporter is working")
print(response.content)