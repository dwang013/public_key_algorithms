import java.math.BigInteger;
import java.io.*;
import java.security.SecureRandom;
import java.util.Arrays;
public class ElgamalDecrypt
{
	private Thread thread[] = new Thread[4];
	
	private BigInteger p = new BigInteger("f7d07342ba3b316e02acd67ad31911d2f522acf3932ab2f6b20500b93697a8294c2b788fc2acae94820e9133ba0d6d2f3703e686f59efc2a447880863810701466391c2a3b552c0535dc2226971f33135a4c27b19f902bf0ded39092894861e1d6cd48f795f7480e65d523e053b50b988ef537896043fcd8e7b9a62a25d34097", 16), 
	g = new BigInteger("e888a8f1b55f6228ea3515f6322528cd5a6a4968d1e35863b868c100e40b97676ce572b2431d4d80189fe870e7e6601df1115c035c9d7b0d4dac3558e7b73d896aea810d3ec4ffcf8ffaf4022ada95ea6ccb8ccaf16f22b7849ef84f9e8e2594e782992d3d91af619eed4f573820a0f10acd99455d619236782f052d5bea69bd", 16), 
	KA = new BigInteger("6fbfef72d2c3a12488887f33736bf9de45680a1a4d6f5b1bdbaeb27487d50b090c5c54dd51a99a2b099e2d95252ba398a1789918c560479f8c546b805c43223efa548ea7b4cb84f01ae46ffb262f2cc42ff3559eb095e9ef120ea8155f0227474040b1c69b0074868c321e64db910386bb5ffdd339f6b55384f0d7f846415aea", 16), 
	q = new BigInteger("7be839a15d1d98b701566b3d698c88e97a915679c995597b5902805c9b4bd414a615bc47e156574a41074899dd06b6979b81f3437acf7e15223c40431c08380a331c8e151daa96029aee11134b8f9989ad2613d8cfc815f86f69c84944a430f0eb66a47bcafba40732ea91f029da85cc477a9bc4b021fe6c73dcd31512e9a04b", 16), 
	y = new BigInteger("b1d72e95571ccf33e4916e5ba2e988314dc0187a7dae7eb9996a4b6e2d4d3ce68afc422b275c0fa20e679c8aab8caeeab30b68cdb5f1f86035b78f6c213a895a03e462e43cff66f424571f274ef7f643a6174a07bd3df30bea415b904a409d628fc01742790961b582a9ca8f28496c50bfae1b29a1c977c3f36b47c5cd811730", 16);
	
	private long decryptTime[] = new long[thread.length], deops[] = new long[thread.length];
	
	private byte data[][] = new byte[thread.length][];
	
	private FileOutputStream outputStream;
	
	private FileInputStream inputStream;
	
	private final int blockSize = 269484032;
	
	private final byte signed = 0;
	
	private int blkSize = 128+129;
	
	public ElgamalDecrypt(String args0, String args1) throws Exception
	{	
		inputStream = new FileInputStream(args0);
			
		outputStream = new FileOutputStream(args1);
	}
	
	private void decrypt() throws Exception
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
					
					int rd = data[num].length/blkSize;
					ByteArrayInputStream in = new ByteArrayInputStream(data[num]);
					ByteArrayOutputStream out = new ByteArrayOutputStream(127*rd);
					long start = System.currentTimeMillis();
					
					int j = 0;
					for(; j < rd; j++)
					{
						byte buf[] = new byte[128];
						
						in.read(buf);
			
						BigInteger K = new BigInteger(1, buf).modPow(KA, p);
				
						K = K.modInverse(p);
						
						buf = new byte[129];
						
						in.read(buf);
						int zeros = buf[0];
						BigInteger m = new BigInteger(1,  Arrays.copyOfRange(buf, 1, buf.length)).multiply(K).mod(p);
						if(m.toByteArray()[0] == signed)
						{
							out.write(new byte[zeros]);
							out.write(Arrays.copyOfRange(m.toByteArray(),1, m.toByteArray().length));
						}
						else
						{
							out.write(new byte[zeros]);
							out.write(m.toByteArray());
						}
						deops[num]++;
					}
					
					decryptTime[num] += System.currentTimeMillis() - start;
					
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
			
		int j = blockSize;
		
		for(; j < fileSize; j+=blockSize)
		{
			int block = blockSize/blkSize;
			
			int eaBlock = block/thread.length;
				
			int remainder = block%thread.length;
				
			for(int i=1; i<data.length; i++)
				data[i] = new byte[eaBlock*blkSize];
			data[0] = new byte[eaBlock*blkSize+remainder*blkSize];
				
			decrypt();
				
			thread[3].join();
		}
			
		j -= blockSize;
			
		int remSize = (int)(fileSize - j);
			
		int block = remSize/blkSize;
			
		int eaBlock = block/thread.length;
				
		int remainder = block%thread.length;
			
		for(int i=1; i<data.length; i++)
			data[i] = new byte[eaBlock*blkSize];
		data[0] = new byte[eaBlock*blkSize+remainder*blkSize];
			
		decrypt();
			
		inputStream.close();
			
		thread[3].join();
			
		outputStream.close();
		
		long totalDecryptTime = 0, totalDeops = 0;
		
		for(int i = 0; i<thread.length; i++)
		{
			totalDecryptTime += decryptTime[i];
			totalDeops += deops[i];
		}
		System.out.println(totalDeops);
		System.out.println(totalDecryptTime);
	}
	
	public static void main(String args[]) throws Exception
	{
		if(args.length < 2)
			System.out.println("usage instrction: java [input file name] [output file name]");
		else
			new ElgamalDecrypt(args[0], args[1]).run();
	}
}