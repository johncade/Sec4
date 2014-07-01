import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Scanner;

/**
 * Created by Jose Bigio & John-Cade on 6/29/14.
 */
public class AES
{
    private static boolean encrypt;
    private static String plainTextFile;
    private static String keyFile;
    private static int[][] key;
    //Fixed Tables

    static int[][] Rcon = {
            {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
                    0x36},
            {0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
            {0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
            {0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    };



    static int[][] lookupTable = {
            {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F,
                    0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
            {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47,
                    0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
            {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7,
                    0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
            {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05,
            0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
            {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A,
                    0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
            {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1,
                    0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
            {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33,
                    0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
            {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38,
                    0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
            {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44,
                    0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
            {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90,
                    0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
            {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24,
                    0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
            {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E,
                    0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
            {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4,
                    0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
            {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6,
                    0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
            {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E,
                    0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
            {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42,
                    0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16},
    };

    static int[][] inverseLookupTable = {
            {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36,
                    0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
            {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F,
                    0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
            {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2,
                    0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
            {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9,
                    0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
            {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68,
                    0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
            {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED,
                    0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
            {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC,
                    0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
            {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F,
                    0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
            {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67,
                    0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
            {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD,
                    0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
            {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29,
                    0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
            {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2,
                    0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
            {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07,
                    0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},{0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5,
            0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
            {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A,
                    0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77,
                    0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}

    };

    ////////////////////////  the mixColumns Tranformation ////////////////////////


    final static int[] LogTable = {
            0,   0,  25,   1,  50,   2,  26, 198,  75, 199,  27, 104,  51, 238, 223,   3,
            100,   4, 224,  14,  52, 141, 129, 239,  76, 113,   8, 200, 248, 105,  28, 193,
            125, 194,  29, 181, 249, 185,  39, 106,  77, 228, 166, 114, 154, 201,   9, 120,
            101,  47, 138,   5,  33,  15, 225,  36,  18, 240, 130,  69,  53, 147, 218, 142,
            150, 143, 219, 189,  54, 208, 206, 148,  19,  92, 210, 241,  64,  70, 131,  56,
            102, 221, 253,  48, 191,   6, 139,  98, 179,  37, 226, 152,  34, 136, 145,  16,
            126, 110,  72, 195, 163, 182,  30,  66,  58, 107,  40,  84, 250, 133,  61, 186,
            43, 121,  10,  21, 155, 159,  94, 202,  78, 212, 172, 229, 243, 115, 167,  87,
            175,  88, 168,  80, 244, 234, 214, 116,  79, 174, 233, 213, 231, 230, 173, 232,
            44, 215, 117, 122, 235,  22,  11, 245,  89, 203,  95, 176, 156, 169,  81, 160,
            127,  12, 246, 111,  23, 196,  73, 236, 216,  67,  31,  45, 164, 118, 123, 183,
            204, 187,  62,  90, 251,  96, 177, 134,  59,  82, 161, 108, 170,  85,  41, 157,
            151, 178, 135, 144,  97, 190, 220, 252, 188, 149, 207, 205,  55,  63,  91, 209,
            83,  57, 132,  60,  65, 162, 109,  71,  20,  42, 158,  93,  86, 242, 211, 171,
            68,  17, 146, 217,  35,  32,  46, 137, 180, 124, 184,  38, 119, 153, 227, 165,
            103,  74, 237, 222, 197,  49, 254,  24,  13,  99, 140, 128, 192, 247, 112,   7};

    final static int[] AlogTable = {
            1,   3,   5,  15,  17,  51,  85, 255,  26,  46, 114, 150, 161, 248,  19,  53,
            95, 225,  56,  72, 216, 115, 149, 164, 247,   2,   6,  10,  30,  34, 102, 170,
            229,  52,  92, 228,  55,  89, 235,  38, 106, 190, 217, 112, 144, 171, 230,  49,
            83, 245,   4,  12,  20,  60,  68, 204,  79, 209, 104, 184, 211, 110, 178, 205,
            76, 212, 103, 169, 224,  59,  77, 215,  98, 166, 241,   8,  24,  40, 120, 136,
            131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206,  73, 219, 118, 154,
            181, 196,  87, 249,  16,  48,  80, 240,  11,  29,  39, 105, 187, 214,  97, 163,
            254,  25,  43, 125, 135, 146, 173, 236,  47, 113, 147, 174, 233,  32,  96, 160,
            251,  22,  58,  78, 210, 109, 183, 194,  93, 231,  50,  86, 250,  21,  63,  65,
            195,  94, 226,  61,  71, 201,  64, 192,  91, 237,  44, 116, 156, 191, 218, 117,
            159, 186, 213, 100, 172, 239,  42, 126, 130, 157, 188, 223, 122, 142, 137, 128,
            155, 182, 193,  88, 232,  35, 101, 175, 234,  37, 111, 177, 200,  67, 197,  84,
            252,  31,  33,  99, 165, 244,   7,   9,  27,  45, 119, 153, 176, 203,  70, 202,
            69, 207,  74, 222, 121, 139, 134, 145, 168, 227,  62,  66, 198,  81, 243,  14,
            18,  54,  90, 238,  41, 123, 141, 140, 143, 138, 133, 148, 167, 242,  13,  23,
            57,  75, 221, 124, 132, 151, 162, 253,  28,  36, 108, 180, 199,  82, 246,   1};



    public static void main(String[] args) throws Exception {


        /*int[][] testKey = {{0x2b,0x28,0xab,0x09},
                           {0x7e,0xae,0xf7,0xcf},
                           {0x15,0xd2,0x15,0x4f},
                           {0x16,0xa6,0x88,0x3c}};*/

       /* int[][] testPlainText = {{0x19,0xa0,0x9a,0xe9},
                                {0x3d,0xf4,0xc6,0xf8},
                                {0xe3,0xe2,0x8d,0x48},
                                {0xbe,0x2b,0x2a,0x08}};
*/

        int[][] testKey = { {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
                            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
                            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
                            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00} };

        int[][] testPlainText = { {0x00,0x44,0x88,0xcc},
                {0x11,0x55,0x99,0xdd},
                {0x22,0x66,0xaa,0xee},
                {0x33,0x77,0xbb,0xff} };



        try{
            getArgs(args);
        }
        catch (Exception ex) {
            System.out.println("Invalid Arguments");
            return;
        }
        //try {
            run();
        //}
        //catch(Exception ex){
          //  System.out.println("Error");
            //return;
        //}

    }

    public static void run() throws IOException {

        if(encrypt) {

            key = getKey();
            print2dArray(key);
            Scanner scan = new Scanner(new FileInputStream(plainTextFile));
            while (scan.hasNextLine()) {
                try {
                    int[][] plainText = getPlaintext(scan);
                    print2dArray(plainText);
                    System.out.println(plainText.toString());
                    encrypt(plainText,key,14);

                } catch (NumberFormatException ex) {
                    System.out.println("Number format error");
                    return;
                }
            }
        }
    }
    /*
1) takes in the scanner and reads one line,
2) constructs a temporary character array from that line.
3) copies that temp char array to a nextLine character array "nextLine" and pads it if necessary.
4) Coverts the characters in nextLine to hex and inserts into "result"
*/
    public static int[][] getPlaintext (Scanner scan) {
        System.out.println("Running getPlaintext");
        int[][] result = new int[4][4];
        char[] temp = scan.nextLine().toCharArray();

        if (temp.length > 32) {
            //skip line
            temp = scan.nextLine().toCharArray();
        }

        char[] nextLine = new char[32];
        //Pad end of next line if short

        for (int i = 0; i < nextLine.length; i++) {
            if (i < temp.length){   nextLine[i] = temp[i];}
            else { nextLine[i] = '0';}
        }

        int col = 0;
        int row = 0;

        for(int i = 0; i < nextLine.length; i+=2) {
            String hex = "";
            for (int k = 0; k < 2; k++) {
                hex = hex + nextLine[i + k];
            }
            int num = Integer.parseInt(hex, 16);

            result[col][row] = num;
            //System.out.println("hex = " + hex);
            //System.out.println("num = " + num);
            col++;
            if(col == 4) { col = 0; row ++; }
        }

        return result;
    }
    public static int[][] getKey() throws FileNotFoundException {
        System.out.println("Running getKey");
        Scanner scan = new Scanner(new FileInputStream(keyFile));
        int[][] result = new int[4][8];
        char[] line = scan.nextLine().toCharArray();
        System.out.println("line length = " + line.length);
        System.out.println(Arrays.toString(line));
        if(line.length < 64){
            throw new IllegalArgumentException("Error with the Key File, invalid key size");
        }
        int col = 0;
        int row = 0;

        for(int i = 0; i < line.length; i+=2) {
            String hex = "";
            for (int k = 0; k < 2; k++) {
                hex = hex + line[i + k];
            }
            int num = Integer.parseInt(hex, 16);

            result[col][row] = num;
            //System.out.println("hex = " + hex);
            //System.out.println("num = " + num);
            col++;
            if(col == 4) { col = 0; row ++; }
        }

        return result;
    }
    public static void getArgs(String[] args) throws Exception {


        if((args.length == 3) && (args[0].charAt(0) == 'e')) encrypt = true;
        else if((args.length == 3) && args[0].charAt(0) == 'd') encrypt = false;
        else {
            throw new IllegalArgumentException("Invalid Arguments");
        }
            keyFile = args[1];
            plainTextFile = args[2];


    }
    public static void encrypt(int[][]state,int[][]key,int numRounds)
    {
        int[][] expandedKey = getexpandedKey(key,numRounds);
        System.out.println("Expanded Key:");
        print2dArray(expandedKey);
        int i;
        for(i = 0;i<numRounds-1;i++)
        {
            System.out.println("\n----------------------------------------------- Round: " + (i+1) + " -----------------------------------------------");
            state = doSubBytes(state, lookupTable);
            System.out.println("\nafter subBytes round " + (i+1));
            print2dArray(state);
            doShiftRows(state);
            System.out.println("\nafter shift rows round " + (i+1));
            print2dArray(state);

            System.out.println("\nafter mixed cols round " + (i+1));
            doMixColumns(state);
            print2dArray(state);

            System.out.println("\nafter addroundkey round " + (i+1));
            doAddRoundKey(state,expandedKey,i);
            print2dArray(state);


        }

        System.out.println("\n----------------------------------------------- Round: " + (i+1) + " -----------------------------------------------");
        state = doSubBytes(state, lookupTable);
        System.out.println("\nafter subBytes round " + numRounds);
        print2dArray(state);
        doShiftRows(state);
        System.out.println("\nafter shift rows round " + numRounds);
        print2dArray(state);

        System.out.println("\nafter addroundkey round " + numRounds);
        doAddRoundKey(state,expandedKey,numRounds-1);
        print2dArray(state);


    }

    public static void decrypt(int[][]state,int[][]key,int numRounds)
    {
        int[][] expandedKey = getexpandedKey(key,numRounds);
        System.out.println("Expanded Key:");
        print2dArray(expandedKey);
        int i;
        for(i = 0;i<numRounds-1;i++)
        {
            System.out.println("\n----------------------------------------------- Round: " + (i+1) + " -----------------------------------------------");
            state = doSubBytes(state, lookupTable);
            System.out.println("\nafter subBytes round " + (i+1));
            print2dArray(state);
            doShiftRows(state);
            System.out.println("\nafter shift rows round " + (i+1));
            print2dArray(state);

            System.out.println("\nafter mixed cols round " + (i+1));
            doMixColumns(state);
            print2dArray(state);

            System.out.println("\nafter addroundkey round " + (i+1));
            doAddRoundKey(state,expandedKey,i);
            print2dArray(state);


        }

        System.out.println("\n----------------------------------------------- Round: " + (i+1) + " -----------------------------------------------");
        state = doSubBytes(state, lookupTable);
        System.out.println("\nafter subBytes round " + numRounds);
        print2dArray(state);
        doShiftRows(state);
        System.out.println("\nafter shift rows round " + numRounds);
        print2dArray(state);

        System.out.println("\nafter addroundkey round " + numRounds);
        doAddRoundKey(state,expandedKey,numRounds-1);
        print2dArray(state);


    }

    public static void doAddRoundKey(int[][]state,int[][]expandedKey,int roundNum)
    {
        for(int i = 0;i<state[0].length;i++)
        {
            int[] stateCol = getColFrom2dArray(state,i);
            int[] roundKeyCol = getColFrom2dArray(expandedKey,i + state.length*(roundNum+1));
            int[] xored = getXoredArr(stateCol,roundKeyCol);
            copyColTo2dArr(state,xored,i);

        }
    }

    public static void copyColTo2dArr(int[][]arr,int[]col,int colNum)
    {
        for(int i = 0;i<arr.length;i++)
        {
            arr[i][colNum] = col[i];
        }
    }

    public static void doShiftRows(int[][]arr)
    {
        for(int i = 0;i<arr.length;i++)
        {
            arr[i] = getshiftedArr(arr[i],i);
        }
    }

    public static void doMixColumns(int[][]arr)
    {
        for(int i = 0;i<arr[0].length;i++)
        {
            mixColumn2(i,arr);
        }
    }

    public static int[] getshiftedArr(int[]arr,int times)
    {
        int[]result = new int[arr.length];
        for(int i = 0;i<times;i++)
        {
            result[arr.length-times+i] = arr[i];
        }

        for(int i = 0;i<arr.length - times;i++)
        {
            result[i] = arr[times+i];
        }

        return result;
    }


    public static int[][] getexpandedKey(int[][] normalKey,int numRounds)
    {
        //place holder for the expanded key
        int[][] result = new int[normalKey.length][64];



        copyBlockIntoArray(result,normalKey,0);


        //get the first block
        int[][]prevKeyBox = normalKey;

        for(int i = 0;i<6;i++)
        {
            int[][]nextBlock = getExpandedKeyBox(prevKeyBox,i,true);
            copyBlockIntoArray(result,nextBlock,(i+1)*8);
            prevKeyBox = nextBlock;
        }
        int[][]nextBlock = getExpandedKeyBox(prevKeyBox,6,false);
        copyBlockIntoArray(result,nextBlock,(6+1)*8);




        return result;
    }


    public static void copyBlockIntoArray(int[][]array, int[][]block, int startingRow)
    {
        for(int i = 0;i<block.length;i++)
        {
            for(int j = 0;j<block[i].length;j++)
            {
                array[i][j+startingRow] = block[i][j];
            }
        }
    }

    public static int[][] getExpandedKeyBox(int[][]prevBox, int stepNum,boolean completeBlock)
    {

        int[][]result = new int[prevBox.length][prevBox[0].length];


        //grab the last col,shift and sub it
        int[] rotWord = getColFrom2dArray(prevBox,prevBox[0].length-1);

        rotWord = shiftArr(rotWord);

        rotWord = getSubArrayFromLookupTable(rotWord,lookupTable);


        //xor it with rcon and the first col
        int[] xoredArr = getXoredArr(rotWord,getColFrom2dArray(prevBox,0));
        xoredArr = getXoredArr(xoredArr,getColFrom2dArray(Rcon,stepNum)); //stepnum from 0



        //copy it to result
        for(int i = 0;i<prevBox.length;i++)
           result[i][0] = xoredArr[i];


        //complete the  3 next columns
        for(int i = 0;i<prevBox.length;i++)
        {
            for(int j = 1;j<4;j++)
            {
                result[i][j] = prevBox[i][j] ^ result[i][j-1];
            }
        }

        if(!completeBlock) return result;

        //generate the next next column
        int[] temp = getColFrom2dArray(result,3);

        temp = getSubArrayFromLookupTable(temp,lookupTable);

        temp = getXoredArr(temp,getColFrom2dArray(prevBox,4));

        //save it
        for(int i = 0;i<prevBox.length;i++)
            result[i][4] = temp[i];

        //complete the  3 next columns
        for(int i = 0;i<result.length;i++)
        {
            for(int j = 0;j<3;j++)
            {
                result[i][j+5] = result[i][j+4] ^ prevBox[i][j+1+4];
            }
        }






        return result;
    }

    public static int[] shiftArr(int[]arr)
    {
        int[]result = new int[arr.length];
        result[arr.length-1] = arr[0];
        for(int i = 0;i<arr.length-1;i++)
        {
            result[i] = arr[i+1];
        }

        return result;
    }

    public static int[] getXoredArr(int[] arr1, int[]arr2)
    {
        int[]result = new int[arr1.length];
        for(int i = 0;i<arr1.length;i++)
        {
            result[i] = arr1[i] ^ arr2[i];
        }

        return result;
    }

    public static int[] getColFrom2dArray(int[][]arr, int col)
    {
        int[] result = new int[arr.length];
        for(int i = 0;i<arr.length;i++)
        {
            result[i] = arr[i][col];
        }

        return result;
    }

    public static int getByteFromLookupTable(int[][]lookupTable, int element)
    {
        int row = element/16;
        int col = element - (row*16);
        return lookupTable[row][col];
    }


    public static int[][] doSubBytes(int[][] arr, int[][] lookupTable)
    {
        int[][] result = new int[arr.length][arr[0].length];
        for(int i = 0;i<arr.length;i++)
        {
            for(int j = 0;j<arr[i].length;j++)
            {
                result[i][j] = getByteFromLookupTable(lookupTable,arr[i][j]);
            }

        }
        return result;
    }


    public static int[] getSubArrayFromLookupTable(int[]arr, int[][]lookupTable)
    {

        int[]result = new int[arr.length];
        for(int i = 0;i<arr.length;i++)
        {
            result[i] = getByteFromLookupTable(lookupTable,arr[i]);
        }
        return result;
    }



    public static void print2dArray(int[][] arr)
    {
        for(int i = 0;i<arr.length;i++)
        {
            for(int j = 0;j<arr[i].length;j++)
            {
                System.out.print(Integer.toHexString(arr[i][j]) + "\t");
            }
            System.out.println();
        }
    }

    //borrowed from Prof Young
    private static int mul (int a, int b) {
        int inda = (a < 0) ? (a + 256) : a;
        int indb = (b < 0) ? (b + 256) : b;

        if ( (a != 0) && (b != 0) ) {
            int index = (LogTable[inda] + LogTable[indb]);
            int val = (AlogTable[ index % 255 ] );
            return val;
        }
        else
            return 0;
    } // mul

    // In the following two methods, the input c is the column number in
    // your evolving state matrix st (which originally contained
    // the plaintext input but is being modified).  Notice that the state here is defined as an
    // array of bytes.  If your state is an array of integers, you'll have
    // to make adjustments.

    public static void mixColumn2 (int c,int[][]st) {
        // This is another alternate version of mixColumn, using the
        // logtables to do the computation.

        int a[] = new int[4];

        // note that a is just a copy of st[.][c]
        for (int i = 0; i < 4; i++)
            a[i] = st[i][c];

        // This is exactly the same as mixColumns1, if
        // the mul columns somehow match the b columns there.
        st[0][c] = (mul(2,a[0]) ^ a[2] ^ a[3] ^ mul(3,a[1]));
        st[1][c] = (mul(2,a[1]) ^ a[3] ^ a[0] ^ mul(3,a[2]));
        st[2][c] = (mul(2,a[2]) ^ a[0] ^ a[1] ^ mul(3,a[3]));
        st[3][c] = (mul(2,a[3]) ^ a[1] ^ a[2] ^ mul(3,a[0]));
    } // mixColumn2

    public static void invMixColumn2 (int c,int[][]st) {
        int a[] = new int[4];

        // note that a is just a copy of st[.][c]
        for (int i = 0; i < 4; i++)
            a[i] = st[i][c];

        st[0][c] = (byte)(mul(0xE,a[0]) ^ mul(0xB,a[1]) ^ mul(0xD, a[2]) ^ mul(0x9,a[3]));
        st[1][c] = (byte)(mul(0xE,a[1]) ^ mul(0xB,a[2]) ^ mul(0xD, a[3]) ^ mul(0x9,a[0]));
        st[2][c] = (byte)(mul(0xE,a[2]) ^ mul(0xB,a[3]) ^ mul(0xD, a[0]) ^ mul(0x9,a[1]));
        st[3][c] = (byte)(mul(0xE,a[3]) ^ mul(0xB,a[0]) ^ mul(0xD, a[1]) ^ mul(0x9,a[2]));
    } // invMixColumn2

    public static void printArray(int[][] a){
        System.out.println("Printing Array...");
        for(int row = 0; row < a.length; row++){
            for(int col = 0; col < a[0].length; col++){
                System.out.print(a[row][col] + " ");
            }
            System.out.println();
        }
    }
}
