async function toggleSalary(id){
  const el = document.getElementById(`salary-${id}`);
  const isEncrypted = el.classList.contains("encrypted");

  if(isEncrypted){
    el.textContent = "Decrypting…";
    try{
      const res = await fetch(`/api/decrypt/${id}`);
      const data = await res.json();
      if(data.ok){
        el.textContent = `$${data.salary}`;
        el.classList.remove("encrypted");
        el.classList.add("decrypted");
      }else{
        el.textContent = "Error";
      }
    }catch(e){
      el.textContent = "Error";
    }
  }else{
    el.textContent = "Encrypted";
    el.classList.remove("decrypted");
    el.classList.add("encrypted");
  }
}
