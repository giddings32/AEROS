/* AEROS Reference Note Renderer V1 */
(function initializeReferenceNoteRenderer(globalScope){
  "use strict";

  function escapeHtml(value){
    return String(value??"")
      .replace(/&/g,"&amp;")
      .replace(/</g,"&lt;")
      .replace(/>/g,"&gt;")
      .replace(/"/g,"&quot;")
      .replace(/'/g,"&#039;");
  }

  function escapeAttr(value){
    return escapeHtml(value);
  }

  const SAFE_NOTE_TAGS=new Set(["div","span","br","hr","p","strong","em","b","i","u","code","pre","mark","table","thead","tbody","tr","th","td"]);
  const SAFE_NOTE_CLASSES=new Set(["bold-text","line-title","neon-green","neon-red","neon-yellow"]);

  function sanitizeNoteTag(raw){
    const match=String(raw||"").match(/^<\s*(\/?)\s*([a-z][a-z0-9]*)\b([^>]*)>$/i);
    if(!match)return escapeHtml(raw);
    const closing=!!match[1],tag=match[2].toLowerCase();
    if(!SAFE_NOTE_TAGS.has(tag))return escapeHtml(raw);
    if(closing)return `</${tag}>`;
    const classes=[];
    const classMatch=match[3].match(/\bclass\s*=\s*(?:"([^"]*)"|'([^']*)')/i);
    if(classMatch){
      String(classMatch[1]??classMatch[2]??"").split(/\s+/).forEach(name=>{
        if(SAFE_NOTE_CLASSES.has(name)&&!classes.includes(name))classes.push(name);
      });
    }
    const classAttribute=classes.length?` class="${classes.join(" ")}"`:"";
    return `<${tag}${classAttribute}>`;
  }

  function sanitizeNoteHtml(value){
    const source=String(value??"");
    let output="",cursor=0;
    for(const match of source.matchAll(/<[^>]*>/g)){
      output+=escapeHtml(source.slice(cursor,match.index));
      output+=sanitizeNoteTag(match[0]);
      cursor=Number(match.index)+match[0].length;
    }
    output+=escapeHtml(source.slice(cursor));
    return output;
  }

  function markdownInline(value){
    let text=sanitizeNoteHtml(value);
    text=text.replace(/`([^`]+)`/g,(match,code)=>`<code>${code}</code>`);
    text=text.replace(/\*\*([^*]+)\*\*/g,"<strong>$1</strong>");
    text=text.replace(/\[([^\]]+)\]\(([^)]+)\)/g,(match,label,url)=>{
      const safeUrl=String(url||"").trim();
      if(!/^(https?:\/\/|file:\/\/|\/)/i.test(safeUrl))return match;
      return `<a href="${escapeAttr(safeUrl)}" target="_blank" rel="noopener noreferrer">${label}</a>`;
    });
    return text;
  }

  function splitMarkdownTableRow(line){
    let raw=String(line??"").trim();
    if(!raw.includes("|"))return [];
    if(raw.startsWith("|"))raw=raw.slice(1);
    if(raw.endsWith("|"))raw=raw.slice(0,-1);

    const cells=[];
    let cell="";
    let inCode=false;
    for(let index=0;index<raw.length;index++){
      const character=raw[index];
      if(character==="\\"&&raw[index+1]==="|"){
        cell+="|";
        index++;
        continue;
      }
      if(character==="`")inCode=!inCode;
      if(character==="|"&&!inCode){
        cells.push(cell.trim());
        cell="";
        continue;
      }
      cell+=character;
    }
    cells.push(cell.trim());
    return cells;
  }

  function markdownTableAlignment(separatorCell){
    const value=String(separatorCell||"").trim();
    if(!/^:?-{3,}:?$/.test(value))return null;
    if(value.startsWith(":")&&value.endsWith(":"))return "center";
    if(value.endsWith(":"))return "right";
    return "left";
  }

  function markdownTableDefinition(headerLine,separatorLine){
    const headers=splitMarkdownTableRow(headerLine);
    const separators=splitMarkdownTableRow(separatorLine);
    if(!headers.length||headers.length!==separators.length)return null;
    const alignments=separators.map(markdownTableAlignment);
    if(alignments.some(value=>!value))return null;
    return {headers,alignments};
  }

  function renderMarkdownTable(headers,alignments,rows){
    const headerHtml=headers.map((cell,index)=>{
      const alignment=alignments[index]||"left";
      return `<th class="align-${alignment}" scope="col">${markdownInline(cell)}</th>`;
    }).join("");

    const bodyHtml=rows.map(row=>{
      const cells=headers.map((unused,index)=>{
        const alignment=alignments[index]||"left";
        return `<td class="align-${alignment}">${markdownInline(row[index]??"")}</td>`;
      }).join("");
      return `<tr>${cells}</tr>`;
    }).join("");

    return `<div class="note-md-table-wrap"><table class="note-md-table"><thead><tr>${headerHtml}</tr></thead><tbody>${bodyHtml}</tbody></table></div>`;
  }

  function splitCommandNoteCodeLines(lines){
    const commands=[];
    let current=[];

    const flush=()=>{
      if(current.length){
        commands.push(current);
        current=[];
      }
    };

    lines.forEach(line=>{
      const raw=String(line??"");
      const trimmed=raw.trim();
      if(!trimmed){
        flush();
        return;
      }

      if(!current.length){
        current.push(raw);
        return;
      }

      const previous=current[current.length-1].trimEnd();
      const isContinuation=/[\\`^|]$/.test(previous)||/(?:&&|\|\|)$/.test(previous)||/^\s+/.test(raw)||/^[|&)]/.test(trimmed);
      if(isContinuation)current.push(raw);
      else{
        flush();
        current.push(raw);
      }
    });

    flush();
    return commands;
  }

  function renderMarkdownLite(markdown,options={}){
    const lines=String(markdown||"").replace(/\r\n/g,"\n").split("\n");
    const splitCommands=!!options.splitCommands;
    let html="";
    let inCode=false;
    let codeLines=[];
    let codeIndex=0;

    const appendCodeBlock=(blockLines)=>{
      const codeId=`note-code-${Date.now()}-${codeIndex++}`;
      html+=`
        <div class="note-code-wrap">
          <button class="secondary-btn small note-code-copy-btn" type="button" data-copy-code="${codeId}">Copy Code</button>
          <pre class="note-md-code"><code id="${codeId}">${escapeHtml(blockLines.join("\n"))}</code></pre>
        </div>
      `;
    };

    const flushCode=()=>{
      const blocks=splitCommands?splitCommandNoteCodeLines(codeLines):[codeLines];
      blocks.filter(block=>block.length).forEach(appendCodeBlock);
      codeLines=[];
    };

    for(let lineIndex=0;lineIndex<lines.length;lineIndex++){
      const line=lines[lineIndex];
      if(/^```/.test(line.trim())){
        if(inCode){
          flushCode();
          inCode=false;
        }else{
          inCode=true;
          codeLines=[];
        }
        continue;
      }

      if(inCode){
        codeLines.push(line);
        continue;
      }

      const tableDefinition=lineIndex+1<lines.length
        ? markdownTableDefinition(line,lines[lineIndex+1])
        : null;
      if(tableDefinition){
        const rows=[];
        let nextIndex=lineIndex+2;
        while(nextIndex<lines.length){
          const candidate=lines[nextIndex];
          if(!candidate.trim()||!candidate.includes("|"))break;
          const cells=splitMarkdownTableRow(candidate);
          if(!cells.length)break;
          rows.push(cells);
          nextIndex++;
        }
        html+=renderMarkdownTable(tableDefinition.headers,tableDefinition.alignments,rows);
        lineIndex=nextIndex-1;
        continue;
      }

      const trimmed=line.trim();
      if(!trimmed){
        html+='<div class="note-md-blank"></div>';
        continue;
      }

      if(/^---+$/.test(trimmed)){
        html+='<hr class="note-md-hr">';
        continue;
      }

      const heading=trimmed.match(/^(#{1,6})\s+(.+)$/);
      if(heading){
        const level=Math.min(6,heading[1].length);
        html+=`<h${level} class="note-md-heading">${markdownInline(heading[2])}</h${level}>`;
        continue;
      }

      const bullet=trimmed.match(/^[-*+]\s+(.+)$/);
      if(bullet){
        html+=`<div class="note-md-li"><span>•</span><div>${markdownInline(bullet[1])}</div></div>`;
        continue;
      }

      const numbered=trimmed.match(/^\d+\.\s+(.+)$/);
      if(numbered){
        html+=`<div class="note-md-li note-md-numbered"><span>#</span><div>${markdownInline(numbered[1])}</div></div>`;
        continue;
      }

      if(/^<\/?(div|span|br|hr|p|strong|em|b|i|u|code|pre|mark|table|thead|tbody|tr|th|td)\b/i.test(trimmed)){
        html+=sanitizeNoteHtml(trimmed);
        continue;
      }

      html+=`<p>${markdownInline(line)}</p>`;
    }

    if(inCode)flushCode();
    return html;
  }

  function bindCodeCopies(root=document){
    root.querySelectorAll(".note-code-copy-btn").forEach(button=>{
      button.onclick=async()=>{
        const id=button.getAttribute("data-copy-code");
        const code=id?document.getElementById(id):null;
        const text=code?code.innerText:"";
        try{
          if(typeof globalScope.aerosAuthorizeCommandCopy==="function"&&!(await globalScope.aerosAuthorizeCommandCopy(text)))return;
          await navigator.clipboard.writeText(text);
          const old=button.textContent;
          button.textContent="Copied";
          setTimeout(()=>button.textContent=old||"Copy Code",900);
        }catch{
          alert("Could not copy code block.");
        }
      };
    });
  }

  function referenceNoteSearchText(note){
    const row=note&&typeof note==="object"?note:{};
    const values=[
      row.title,row.description,row.notePath,row.path,row.category,row.module,
      row.stage,row.executionContext,row.taskId,
      ...(Array.isArray(row.tags)?row.tags:[]),
      ...(Array.isArray(row.keywords)?row.keywords:[]),
      ...(Array.isArray(row.serviceHints)?row.serviceHints:[]),
    ];
    return values.filter(value=>value!==undefined&&value!==null).join(" ").toLowerCase();
  }

  function matchesReferenceNoteSearch(note,query){
    const terms=String(query||"").trim().toLowerCase().split(/\s+/).filter(Boolean);
    if(!terms.length)return true;
    const haystack=referenceNoteSearchText(note);
    return terms.every(term=>haystack.includes(term));
  }

  globalScope.AEROSReferenceNoteRenderer=Object.freeze({
    renderMarkdownLite,
    bindCodeCopies,
    sanitizeNoteHtml,
    matchesReferenceNoteSearch,
  });
})(window);
