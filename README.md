# cmdcopy
## gscopy

## Windows file Date.Created, Date.Modified on File Copy, Move & Write 

### Usage: gscopy source destination [copy|xcopy|move|write] [blocksize]
- *gscopy* _source_ _destination_ 
  [ _copies source to destination, if source file exists_ ]
- *gscopy* _source_ _destination_ *move*
  [ _moves source file to destination_ ]
- *gscopy* _source_ _dest_ *write*
  [ _reads source file into mem buffer, then writes full buffer at once to dest file_ ]
- *gscopy* _src_ _dest_ *write* 16384
  [ _read & write 16384 bytes block data (same as dd if=src of=dest bs=16384)_ ]


### File.Copy
File.Copy, no matter if made with Windows Explorer, command copy, xcopy or programs, that use File.Copy Windows Api call, creates a new file or overwrites an existing file, where
Created Date = now,
Last Modified Date = Last Modified Date of original file

### File.Move
File.Move, no matter if made with Windows Explorer, Command move or programs, that use File.Move Windows Api call, creates a new file or overwrites an existing file, where
Created Date = created Date of original file
Last Modified Date = Last Modified Date of original file

### File.Write
File Write, no matter, if Console Application, Windows Application or Windows Service or what ever,
creates a new or overwrites an existing file, where 
Created Date = now
Last Modified Date = now
