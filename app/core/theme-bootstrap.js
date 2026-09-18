/* Apply the saved visual theme before stylesheet paint. */
(function applySavedAerosTheme(documentRoot){
  "use strict";
  try{
    documentRoot.setAttribute("data-theme",window.localStorage.getItem("appTheme")||"blue");
  }catch(error){
    documentRoot.setAttribute("data-theme","blue");
  }
})(document.documentElement);
