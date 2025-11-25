// Pequenas interações
document.addEventListener('DOMContentLoaded', ()=>{
  // animação sutil nos valores
  const amt = document.querySelector('.amount')
  if(amt){
    amt.animate([{transform:'translateY(6px)', opacity:0},{transform:'translateY(0)',opacity:1}],{duration:600,easing:'cubic-bezier(.2,.8,.2,1)'});
  }
});
