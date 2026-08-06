from llm_client import get_llm

#llm = get_llm("anthropic/claude-3.5-haiku-20241022")
#llm = get_llm("anthropic/claude-haiku-latest")
#llm = get_llm("anthropic/claude-3-haiku")
llm = get_llm("anthropic/claude-3-haiku")
response = llm.invoke("Say only: Claude verifier is working")
print(response.content)