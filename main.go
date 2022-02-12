/*
........................................................................................
. Developer -> ArkAngeL43
. Based off -> The image injection lib, my own forked verison of this lib
. Orgin     -> Base0
. Type      -> CLI
. IMG Form  -> PNG
. DATA FORM -> IN=BASED64/BINARY OUT=ASCII
. Organ     -> Scare_Sec_Hackers Offical cyber security team
.
.
.
. This program uses a rewrite of the lib imginject from the authors of the BHG Book
. it is meant to be used for image injection and stegenography purposes
.
. I felt the reason this lib needed to be modified was because of how little information it was
. giving out, personally this is my opinion but i think it would be better if libs like this
. gave out more information
*/
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/bndr/gotabulate"
	"github.com/spf13/pflag"
)

//setting variables
var (
	flags = pflag.FlagSet{SortFlags: false}
	opts  CmdLineOpts
	// these are all pretty defualt to have in my scripts
	// i use it alot XD
	banner     = "txt/banner.txt"
	clear_hex  = "\x1b[H\x1b[2J\x1b[3J"
	now        = time.Now()
	formatDate = now.Format("15:04:05")
	BLK        = "\033[0;30m"
	RED        = "\033[0;31m"
	GRN        = "\033[0;32m"
	YEL        = "\033[0;33m"
	BLU        = "\033[0;34m"
	MAG        = "\033[0;35m"
	CYN        = "\033[0;36m"
	WHT        = "\033[0;37m"
	BBLK       = "\033[1;30m"
	BRED       = "\033[1;31m"
	BGRN       = "\033[1;32m"
	BYEL       = "\033[1;33m"
	BBLU       = "\033[1;34m"
	BMAG       = "\033[1;35m"
	BCYN       = "\033[1;36m"
	BWHT       = "\033[1;37m"
	UBLK       = "\033[4;30m"
	URED       = "\033[4;31m"
	UGRN       = "\033[4;32m"
	UYEL       = "\033[4;33m"
	UBLU       = "\033[4;34m"
	UMAG       = "\033[4;35m"
	UCYN       = "\033[4;36m"
	UWHT       = "\033[4;37m"
	BLKB       = "\033[40m"
	REDB       = "\033[41m"
	GRNB       = "\033[42m"
	YELB       = "\033[43m"
	BLUB       = "\033[44m"
	MAGB       = "\033[45m"
	CYNB       = "\033[46m"
	WHTB       = "\033[47m"
	BLKHB      = "\033[0;100m"
	REDHB      = "\033[0;101m"
	GRNHB      = "\033[0;102m"
	YELHB      = "\033[0;103m"
	BLUHB      = "\033[0;104m"
	MAGHB      = "\033[0;105m"
	CYNHB      = "\033[0;106m"
	WHTHB      = "\033[0;107m"
	HBLK       = "\033[0;90m"
	HRED       = "\033[0;91m"
	HGRN       = "\033[0;92m"
	HYEL       = "\033[0;93m"
	HBLU       = "\033[0;94m"
	HMAG       = "\033[0;95m"
	HCYN       = "\033[0;96m"
	HWHT       = "\033[0;97m"
	BHBLK      = "\033[1;90m"
	BHRED      = "\033[1;91m"
	BHGRN      = "\033[1;92m"
	BHYEL      = "\033[1;93m"
	BHBLU      = "\033[1;94m"
	BHMAG      = "\033[1;95m"
	BHCYN      = "\033[1;96m"
	BHWHT      = "\033[1;97m"
	chunkType  string
	IMG_png    MetaChunk
	m          MetaChunk
)

// start out with restructuring the lib into a built in module
// this part is the options
type CmdLineOpts struct {
	Input    string
	Output   string
	Meta     bool
	Suppress bool
	Offset   string
	Inject   bool
	Payload  string
	Type     string
	Encode   bool
	Decode   bool
	Key      string
	Test_f   bool
}

// this second part will be the commands.go file

const (
	endChunkType = "IEND"
)

//Header holds the first byte (aka magic byte)
type Header struct {
	Header uint64 //  0:8
}

//Chunk represents a data byte chunk
type Chunk struct {
	Size uint32
	Type uint32
	Data []byte
	CRC  uint32
}

//MetaChunk inherits a Chunk struct
type MetaChunk struct {
	Chk    Chunk
	Offset int64
}

// add return error function
func che(err error, msg string, exit int) {
	if err != nil {
		fmt.Println(RED, "[!] Error: Fatal: ", msg, err)
		os.Exit(exit)
	}
}

func hex_conv(data string) string {
	// replace 0x or 0X with empty String
	numberStr := strings.Replace(data, "0x", "", -1)
	numberStr = strings.Replace(numberStr, "0X", "", -1)
	return numberStr
}

// hex dumper
func dumper(file string, buffer int) {
	hexed, err := os.Open(file)
	che(err, " Could not read or open this file -> ", 1)
	defer hexed.Close()
	reader := bufio.NewReader(hexed)
	buffer_ := make([]byte, buffer)
	fmt.Println("\n\t\033[38m[+] HEX DUMPING IN 5 SECONDS")
	time.Sleep(5 * time.Second)
	for {
		_, err := reader.Read(buffer_)
		che(err, "Could not read or properly set buffer", 1)
		fmt.Printf("\033[31m%s", hex.Dump(buffer_))
	}
}

//ProcessImage is the wrapper to parse PNG bytes
func (mc *MetaChunk) ProcessImage(b *bytes.Reader, c *CmdLineOpts) {
	mc.validate(b)
	// this will be for second file reading
	// omitting again ArkAngeL43 -> Line 78
	// conversion !c.Encode
	if (c.Offset != "") && (!c.Encode && !c.Decode) {
		m.Chk.Data = []byte(c.Payload)
		m.Chk.Type = m.strToInt(c.Type)
		m.Chk.Size = m.createChunkSize()
		m.Chk.CRC = m.createChunkCRC()
		bm := m.marshalData()
		bmb := bm.Bytes()
		fmt.Print("\033[31m [INFO]   ", BLU, formatDate, "   -> Payload Original -> ", []byte(c.Payload), "\n")
		fmt.Print("\033[31m [INFO]   ", BLU, formatDate, "   -> Payload          -> ", m.Chk.Data, "\n")
		WriteData(b, c, bmb)
		fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " -> (NOTE: This will be a before and after Offset comparision)")
		var out string
		fmt.Print(RED, "[INFO] ", BLU, formatDate, RED, " -> Would you like to get the new IEND OFFSET (Y/n)> ")
		fmt.Scanf("%s", &out)
	}
	if (c.Offset != "") && c.Encode {
		m.Chk.Data = XorEncode([]byte(c.Payload), c.Key)
		m.Chk.Type = m.strToInt(c.Type)
		m.Chk.Size = m.createChunkSize()
		m.Chk.CRC = m.createChunkCRC()
		bm := m.marshalData()
		bmb := bm.Bytes()
		fmt.Printf("Payload Original: % X\n", []byte(c.Payload))
		fmt.Printf("Payload Encode: % X\n", m.Chk.Data)
		WriteData(b, c, bmb)
	}
	if (c.Offset != "") && c.Decode {
		offset, _ := strconv.ParseInt(c.Offset, 10, 64)
		b.Seek(offset, 0)
		m.readChunk(b)
		origData := m.Chk.Data
		m.Chk.Data = XorDecode(m.Chk.Data, c.Key)
		m.Chk.CRC = m.createChunkCRC()
		bm := m.marshalData()
		bmb := bm.Bytes()
		fmt.Printf("Payload Original: % X\n", origData)
		fmt.Printf("Payload Decode: % X\n", m.Chk.Data)
		WriteData(b, c, bmb)
	}
	if c.Meta {
		count := 1 //Start at 1 because 0 is reserved for magic byte
		// first start by asking the user if they would like to just locate the IEND or main
		// injection offset point
		scanner := bufio.NewReader(os.Stdin)
		fmt.Print("\nWould you like to locate just the IEND chunk? and injectable offset <y/n > ")
		fmt.Println("")
		fmt.Println(YEL, "\n[!] If you wanted to you can type -> chunk_finish to get all data chunks in the image as well")
		// bufio would not exactly work IO module gives EOF as a END OF INPUT to take in
		// 2022/02/12 02:06:11 EOF
		// exit status 1
		for {
			text, _ := scanner.ReadString('\n')
			// convert CRLF to LF
			text = strings.Replace(text, "\n", "", -1)
			if strings.Compare("y", text) == 0 {
				for chunkType != endChunkType {
					mc.getOffset(b)
					mc.readChunk(b)
					if mc.chunkTypeToString() == "IEND" {
						// we should probobly use a caller for this so- calling
						// func inter_change with print might be a good solution
						// ~ ArkAngeL43
						// got error upon changing
						//  [!] Error: Fatal:  Could not parse UINT ->  strconv.ParseUint: parsing "IEND": invalid syntax
						// so in order to fix this convert mc.offset to a INT64
						//mcm := fmt.Sprint(mc.Offset)
						// data using sprintf returns
						// 5526376 or 545368 where 1st INT64 is in the table and INT64 SECOND is outside the table
						// find way to output the hex of the offset, since its not displaying
						//output, err := strconv.ParseUint(hex_conv(mcm), 16, 64)
						//che(err, "Could not parse UINT -> ", 1)
						//fmt.Printf("[!] Chunk offset %#02x", mc.Offset)
						//
						// log: error solved, wasnt using right format string to parse
						// conv function not needed
						//
						data_mcm_hex := fmt.Sprintf("%#02x", mc.Offset)
						row_1 := []interface{}{mc.chunkTypeToString(), mc.Offset, data_mcm_hex}
						t := gotabulate.Create([][]interface{}{row_1})
						t.SetHeaders([]string{"Chunk Type", "Location Injectable OFFSET", "Injectable OFFSET HEX Translation"})
						t.SetEmptyString("None")
						t.SetAlign("right")
						fmt.Println("\n\033[32m Found IEND chunk -> \n", t.Render("grid"))
						fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " -> This data seems to be the actuall injectable point, would you like to hex dump the file to be sure this IEND tag is at the direct OFFSET of  -> ", mc.Offset)
						scanner := bufio.NewReader(os.Stdin)
						fmt.Println(YEL, "[INFO] ", BLU, formatDate, "Yes/NO > ")
						for {
							text, _ := scanner.ReadString('\n')
							// convert CRLF to LF
							text = strings.Replace(text, "\n", "", -1)
							if strings.Compare("Yes", text) == 0 || strings.Compare("YES", text) == 0 || strings.Compare("y", text) == 0 || strings.Compare("yes", text) == 0 {
								dumper(c.Input, 256)
							}
							if strings.Compare("n", text) == 0 || strings.Compare("No", text) == 0 || strings.Compare("NO", text) == 0 || strings.Compare("no", text) == 0 {
								fmt.Println("\n\nFinished Data skimmer in -> ", formatDate)
								os.Exit(0)
							}
							break
						}
					}
				}
			}
			if strings.Compare("n", text) == 0 || strings.Compare("chunk_finish", text) == 0 || strings.Compare("no", text) == 0 || strings.Compare("No", text) == 0 {
				for chunkType != endChunkType {
					mc.getOffset(b)
					mc.readChunk(b)
					// change to this was throwing everything into a data table, felt like it was better organized like
					offset_conf := fmt.Sprintf("%#02x", mc.Offset)
					chunk_ := mc.chunkTypeToString()
					counter := strconv.Itoa(count)
					crit := mc.checkCritType()
					chunk_len := strconv.Itoa(int(mc.Chk.Size))
					row_1 := []interface{}{offset_conf, chunk_, counter, crit, chunk_len}
					t := gotabulate.Create([][]interface{}{row_1})
					t.SetHeaders([]string{"Offset", "Chunk", "Chunk Number", "Chunk Importance", "Chunk Length"})
					t.SetEmptyString("None")
					t.SetAlign("right")
					fmt.Println("\033[31m\n", t.Render("grid"))

					//
					//fmt.Println("---- Chunk # " + strconv.Itoa(count) + " ----")
					//fmt.Printf("Chunk Offset: %#02x\n", mc.Offset)
					//fmt.Printf("Chunk Length: %s bytes\n", strconv.Itoa(int(mc.Chk.Size)))
					//fmt.Printf("Chunk Type: %s\n", mc.chunkTypeToString())
					//fmt.Printf("Chunk Importance: %s\n", mc.checkCritType())
					// omit to !c.Supress
					// ArkAngeL43 -> Change line 12
					if c.Suppress {
						fmt.Printf("Chunk Data: %s\n", "Suppressed")
					}
					fmt.Printf("\033[37mChunk CRC => %x\n", mc.Chk.CRC)
					chunkType = mc.chunkTypeToString()
					count++
				}
				break
			}
			// why?
			// Loop is terminated unconditionally
			// it works but why the warningS?
			break
		}

		fmt.Println("[+] Finished...")
	}
	// locating the offset
	// going to use standard flags for this
	// cant use STD flags so make it mandatory
	/*
		if *offset_yn {
			for chunkType != endChunkType {
				mc.getOffset(b)
				mc.readChunk(b)
				if mc.chunkTypeToString() == "IEND" {
					fmt.Println("found IEND chunk")
				} else {
					fmt.Println("nothing")
				}
			}
		}
	*/

}

func (mc *MetaChunk) marshalData() *bytes.Buffer {
	bytesMSB := new(bytes.Buffer)
	if err := binary.Write(bytesMSB, binary.BigEndian, mc.Chk.Size); err != nil {
		log.Fatal(err)
	}
	if err := binary.Write(bytesMSB, binary.BigEndian, mc.Chk.Type); err != nil {
		log.Fatal(err)
	}
	if err := binary.Write(bytesMSB, binary.BigEndian, mc.Chk.Data); err != nil {
		log.Fatal(err)
	}
	if err := binary.Write(bytesMSB, binary.BigEndian, mc.Chk.CRC); err != nil {
		log.Fatal(err)
	}

	return bytesMSB
}

func (mc *MetaChunk) readChunk(b *bytes.Reader) {
	mc.readChunkSize(b)
	mc.readChunkType(b)
	mc.readChunkBytes(b, mc.Chk.Size)
	mc.readChunkCRC(b)
}

func (mc *MetaChunk) readChunkSize(b *bytes.Reader) {
	if err := binary.Read(b, binary.BigEndian, &mc.Chk.Size); err != nil {
		log.Fatal(err)
	}
}

func (mc *MetaChunk) readChunkType(b *bytes.Reader) {
	if err := binary.Read(b, binary.BigEndian, &mc.Chk.Type); err != nil {
		log.Fatal(err)
	}
}

func (mc *MetaChunk) readChunkBytes(b *bytes.Reader, cLen uint32) {
	mc.Chk.Data = make([]byte, cLen)
	if err := binary.Read(b, binary.BigEndian, &mc.Chk.Data); err != nil {
		log.Fatal(err)
	}
}

func (mc *MetaChunk) readChunkCRC(b *bytes.Reader) {
	if err := binary.Read(b, binary.BigEndian, &mc.Chk.CRC); err != nil {
		log.Fatal(err)
	}
}

func (mc *MetaChunk) getOffset(b *bytes.Reader) {
	offset, _ := b.Seek(0, 1)
	mc.Offset = offset
}

func (mc *MetaChunk) chunkTypeToString() string {
	h := fmt.Sprintf("%x", mc.Chk.Type)
	decoded, _ := hex.DecodeString(h)
	result := fmt.Sprintf("%s", decoded)
	return result
}

func (mc *MetaChunk) checkCritType() string {
	fChar := string([]rune(mc.chunkTypeToString())[0])
	if fChar == strings.ToUpper(fChar) {
		return "Critical"
	}
	return "Ancillary"
}

func (mc *MetaChunk) validate(b *bytes.Reader) {
	var header Header

	if err := binary.Read(b, binary.BigEndian, &header.Header); err != nil {
		log.Fatal(err)
	}

	bArr := make([]byte, 8)
	binary.BigEndian.PutUint64(bArr, header.Header)

	if string(bArr[1:4]) != "PNG" {
		log.Fatal("Provided file is not a valid PNG format")
	} else {
		fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " -> ", bArr[1:4], " Came back as a VALID HEADER")
	}
}

func (mc *MetaChunk) createChunkSize() uint32 {
	return uint32(len(mc.Chk.Data))
}

func (mc *MetaChunk) createChunkCRC() uint32 {
	bytesMSB := new(bytes.Buffer)
	if err := binary.Write(bytesMSB, binary.BigEndian, mc.Chk.Type); err != nil {
		log.Fatal(err)
	}
	if err := binary.Write(bytesMSB, binary.BigEndian, mc.Chk.Data); err != nil {
		log.Fatal(err)
	}
	return crc32.ChecksumIEEE(bytesMSB.Bytes())
}

func (mc *MetaChunk) strToInt(s string) uint32 {
	t := []byte(s)
	return binary.BigEndian.Uint32(t)
}

//
//
// third part with be the utils final part
//
///writer
func WriteData(r *bytes.Reader, c *CmdLineOpts, b []byte) {
	offset, err := strconv.ParseInt(c.Offset, 10, 64)
	che(err, "[!] Could not parse Integer to STRCONV during offset seeking", 1)
	// in later up's check if the file exists and if it does create a seperate function to create and inject a new file
	w, err := os.OpenFile(c.Output, os.O_RDWR|os.O_CREATE, 0777)
	che(err, "Could not read the file, this might be due to the fact the file doesnt exist D:", 1)
	r.Seek(0, 0)

	var buff = make([]byte, offset)
	r.Read(buff)
	w.Write(buff)
	w.Write(b)
	if c.Decode {
		r.Seek(int64(len(b)), 1) // right bitshift to overwrite encode chunk
		fmt.Println(RED, "[INFO]", BLU, formatDate, RED, " -> Found right bitshift")
	}
	_, err = io.Copy(w, r)
	if err == nil {
		fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " -> Success injecting, created file    \t", c.Output)
	}
	// now run a new exif data table
	fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " -> Reading and dumping new file")
	call_perl_s(c.Output)
}

// reader
//PreProcessImage reads to buffer from file handle
func PreProcessImage(dat *os.File) (*bytes.Reader, error) {
	stats, err := dat.Stat()
	if err != nil {
		log.Fatal(err)
	}

	var size = stats.Size()
	b := make([]byte, size)

	bufR := bufio.NewReader(dat)
	if _, err := bufR.Read(b); err != nil {
		log.Fatal(err)
	}

	bReader := bytes.NewReader(b)

	return bReader, err
}

// encoder
func encodeDecode(input []byte, key string) []byte {
	var bArr = make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		bArr[i] += input[i] ^ key[i%len(key)]
	}
	return bArr
}

//XorEncode returns encoded byte array
func XorEncode(decode []byte, key string) []byte {
	return encodeDecode(decode, key)
}

//XorDecode returns decoded byte array
func XorDecode(encode []byte, key string) []byte {
	return encodeDecode(encode, key)
}

// perl caller
func call_perl_s(image string) {

	prg := "perl"
	arg1 := "exif.pl"
	arg5 := "-f"
	arg2 := image
	cmd := exec.Command(prg, arg1, arg5, arg2)
	stdout, err := cmd.Output()
	che(err, "Could not run perl file -<> ", 1)
	fmt.Print(string(stdout))

}

// check if the image exists
func exists_(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// this is what was in the main file and where modification to the module happens

func init() {
	flags.StringVarP(&opts.Input, "input", "i", "", "Path to the original image file")
	flags.StringVarP(&opts.Output, "output", "o", "", "Path to output the new image file")
	flags.BoolVarP(&opts.Meta, "meta", "m", false, "Display the actual image meta details")
	flags.BoolVarP(&opts.Suppress, "suppress", "s", false, "Suppress the chunk hex data (can be large)")
	flags.StringVar(&opts.Offset, "offset", "", "The offset location to initiate data injection")
	flags.BoolVar(&opts.Inject, "inject", false, "Enable this to inject data at the offset location specified")
	flags.StringVar(&opts.Payload, "payload", "", "Payload is data that will be read as a byte stream")
	flags.StringVar(&opts.Type, "type", "rNDm", "Type is the name of the Chunk header to inject")
	flags.StringVar(&opts.Key, "key", "", "The enryption key for payload")
	flags.BoolVar(&opts.Encode, "encode", false, "XOR encode the payload")
	flags.BoolVar(&opts.Decode, "decode", false, "XOR decode the payload")
	flags.BoolVar(&opts.Test_f, "compare", true, "Call a function to compare the previous IEND OFFSET to the new IEND OFFSET of the injected image")
	// flag for look
	// setting defualt
	flags.Lookup("type").NoOptDefVal = "rNDm"
	flags.Usage = usage
	flags.Parse(os.Args[1:])

	if flags.NFlag() == 0 {
		flags.PrintDefaults()
		os.Exit(1)
	}
	if opts.Input == "" {
		log.Fatal("Fatal: The --input flag is required")
	}
	if opts.Offset != "" {
		byteOffset, _ := strconv.ParseInt(opts.Offset, 0, 64)
		opts.Offset = strconv.FormatInt(byteOffset, 10)
	}
	// should omit comparision to bool constant, modified and simplified to !opts.Meta
	// ArkAngeL43
	if opts.Suppress && (!opts.Meta) {
		log.Fatal("Fatal: The --meta flag is required when using --suppress")
	}
	if opts.Meta && (opts.Offset != "") {
		log.Fatal("Fatal: The --meta flag is mutually exclusive with --offset")
	}
	if opts.Inject && (opts.Offset == "") {
		log.Fatal("Fatal: The --offset flag is required when using --inject")
	}
	if opts.Inject && (opts.Payload == "") {
		log.Fatal("Fatal: The --payload flag is required when using --inject")
	}
	if opts.Inject && opts.Key == "" {
		fmt.Println("Warning: No key provided. Payload will not be encrypted")
	}
	if opts.Encode && opts.Key == "" {
		log.Fatal("Fatal: The --encode flag requires a --key value")
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Example Usage: %s -i in.png -o out.png --inject --offset 0x85258 --payload 1234\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Example Encode Usage: %s -i in.png -o encode.png --inject --offset 0x85258 --payload 1234 --encode --key secret\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Example Decode Usage: %s -i encode.png -o decode.png --offset 0x85258 --decode --key secret\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Flags: %s {OPTION]...\n", os.Args[0])
	flags.PrintDefaults()
	os.Exit(0)
}

// banner
func banner_m(bannerf, clear_, color string) {
	fmt.Println(clear_)
	content, err := ioutil.ReadFile(bannerf)
	che(err, "Could not open banner file got error -> ", 1)
	fmt.Println(color, string(content))
}

func main() {
	banner_m(banner, clear_hex, BLU)
	if exists_(opts.Input) {
		fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " -> File Exists \t", opts.Input)
	} else {
		fmt.Println(RED, "[!] WARN: FILE  -> ", BLU, formatDate, opts.Input, " \tDOES NOT EXIST")
	}
	fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " -> Opening file   \t", opts.Input)
	dat, err := os.Open(opts.Input)
	// check err, got warning on checking error before defer
	che(err, "Could not open file? Got err -> ", 1)
	fmt.Println(RED, "[INFO] ", BLU, formatDate, RED, " -> ", opts.Input, "\t Successfully opened")
	defer dat.Close()
	bReader, err := PreProcessImage(dat)
	che(err, " Could not process image got err -> ", 1)
	call_perl_s(opts.Input)
	IMG_png.ProcessImage(bReader, &opts)
}
