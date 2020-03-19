import java.math.BigInteger;
import java.io.*;
import java.security.SecureRandom;
import java.util.Arrays;
public class RSAEncrypt
{
	private Thread thread[] = new Thread[4];
	
	private BigInteger p = new BigInteger("9e4a460db7a739911200732b6a0a792e49dc503a98ac2e6d1a5f7b30dfabbe7f66799440e68a978303a45c339c514a38b09de4c7504073f1a9b17c0422cac663",16), 
	q = new BigInteger("f85890cc4f686965d3fda174187a83c6c3d61a864f2817d7dba3c22fb9519469a78f253ad2a3d5af9749f0f36478aed0dba9428d0340960c9eb0f6acd1311025", 16), 
	n = new BigInteger("998eb6ed7a522672db4e9edd7aa4e073ca12d21d1105f00210459a7fd969730b8853629228991a5994d2ba2c0f9526872178966bf3d674171784d663e9800a5b33d180c40f72830b199e3827a152e7f20708ee801115eeffc56896421f821b744a6ff5a25426cd5e81f89e6a957ffef9b8feeeefb196ea747489d0107fa7dc4f", 16), 
	e = new BigInteger("5b3f7aab19091cb1c7f3db68a53747f99067ebfe7a88c2d81bbea239215e7673c8703f85625ca4442ac94c7f0d8bea95a4efe58fa1e92efd2fb6e96901a1dadd96d7c63d15766b9ee5aca8303511b2b073a9b4f6fe0ef3de0d6b24d946458dd0331088036310a857b8025311684e834c0fbfd51dad1a03c0efdee9043ad5771b", 16), 
	d = new BigInteger("2f45789c455b1cdf349491fd4f6f9d3d9b0fd77186f4c4368d75205674bd3f73c37a188f1548d1367bb88a11c54f3b913bf0ceecdc4980cbe9d9d23e9f9e52845071a17b7aab50db2dc70e19ba1d9f4e552b95fd4c22e4f2bc30d7248ca48d1aea756278dfcfc4d4cbb78fd01f7d2c7414df9dbae79f37e556e0cfb9e791eb3", 16);
	
	private long encryptTime[] = new long[thread.length], enops[] = new long[thread.length];
	
	private byte data[][] = new byte[thread.length][];
	
	private FileOutputStream outputStream;
	
	private FileInputStream inputStream;
	
	private final int blockSize = 135266304;
	
	private final byte signed = 0;
	
	public RSAEncrypt(String args0, String args1) throws Exception
	{	
		inputStream = new FileInputStream(args0);
		
		outputStream = new FileOutputStream(args1);
	}
	
	private void encrypt() throws Exception
	{			
		for(int i = 0; i < thread.length; i++)
		{
			inputStream.read(data[i]);
			final int num = i;
			thread[i] = new Thread(() ->
			{
				try
				{
					int threadNum = num;
					
					int rd = data[num].length/127;
					int rem = data[num].length%127;
					ByteArrayInputStream in = new ByteArrayInputStream(data[num]);
					ByteArrayOutputStream out = new ByteArrayOutputStream(rd*129 + (rem == 0? 0 : 129));
					byte buf[] = new byte[127];
					
					long start = System.currentTimeMillis();
					
					int j = 0;
					for(; j < rd; j++)
					{
						in.read(buf);
						int k = 0;
						for(; k < buf.length && buf[k] == signed; k++);
						byte zeros = (byte)k;
						out.write(zeros);
						BigInteger C = new BigInteger(1, buf).modPow(e,n);
						if(C.toByteArray()[0] == signed)
						{
							out.write(new byte[128 - (C.toByteArray().length-1)]);
							out.write(Arrays.copyOfRange(C.toByteArray(),1, C.toByteArray().length));
						}
						else
						{
							out.write(new byte[128 - C.toByteArray().length]);
							out.write(C.toByteArray());
						}
						enops[num]++;
					}

					buf = new byte[rem];
					in.read(buf);
					int k = 0;
					for(; k < buf.length && buf[k] == signed; k++);
					byte zeros = (byte)k;
					out.write(zeros);
					BigInteger C = new BigInteger(1, buf).modPow(e,n);
					if(C.toByteArray()[0] == signed)
					{
						out.write(new byte[128 - (C.toByteArray().length-1)]);
						out.write(Arrays.copyOfRange(C.toByteArray(),1, C.toByteArray().length));
					}
					else
					{
						out.write(new byte[128 - C.toByteArray().length]);
						out.write(C.toByteArray());
					}
					
					encryptTime[num] += System.currentTimeMillis() - start;
					
					if(threadNum == 0)
					{
						out.writeTo(outputStream);
					}
					else
					{
						thread[num - 1].join();
						
						out.writeTo(outputStream);
					}
				}
				catch(Exception e)
				{
					e.printStackTrace();
				}
			});
				
			thread[i].start();
		}
	}
	
	public void run() throws Exception
	{
		long fileSize = inputStream.getChannel().size();
		
		long j = blockSize;
			
		for(; j < fileSize; j+=blockSize)
		{
			int eaBlock = blockSize/thread.length;
				
			int remainder = blockSize%thread.length;
				
			for(int i=1; i<data.length; i++)
					data[i] = new byte[eaBlock];
			data[0] = new byte[eaBlock+remainder];
				
			encrypt();
				
			thread[3].join();
		}
			
		j -= blockSize;
			
		int remSize = (int)(fileSize - j);
			
		int eaBlock = remSize/thread.length;
			
		int remainder = remSize%thread.length;
			
		for(int i=1; i<data.length; i++)
			data[i] = new byte[eaBlock];
		data[0] = new byte[eaBlock+remainder];
			
		encrypt();
			
		inputStream.close();
			
		thread[3].join();
		
		outputStream.close();
		
		long totalEncryptTime = 0, totalEnops = 0;
		
		for(int i = 0; i<thread.length; i++)
		{
			totalEncryptTime += encryptTime[i];
			totalEnops += enops[i];
		}
		System.out.println(totalEnops);
		System.out.println(totalEncryptTime);
	}
	
	public static void main(String args[]) throws Exception
	{
		if(args.length < 2)
			System.out.println("usage instrction: java [input file name] [output file name]");
		else
			new RSAEncrypt(args[0], args[1]).run();
	}
}