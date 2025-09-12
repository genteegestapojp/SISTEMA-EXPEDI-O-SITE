import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  'https://owsoweqqttcmuuaohxke.supabase.co',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im93c293ZXFxdHRjbXV1YW9oeGtlIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1NjIyNDk5MCwiZXhwIjoyMDcxODAwOTkwfQ.YGwitRA4HF4TiYKtah00OIcvh9WEN1bFPqUoODfr3a8'
);

export default async function handler(req, res) {
  // CORS - PERMITIR TODAS AS ORIGENS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,user,password,filial');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    const { user, password, filial } = req.headers;
    const { table, ...queryParams } = req.query;

   if (!user || !password) {
  return res.status(401).json({ error: 'Credenciais de usuário e senha necessárias' });
}

// O cabeçalho 'filial' só é necessário para tabelas que dependem dele
if (!['filiais', 'acessos'].includes(table) && !filial) {
    return res.status(401).json({ error: 'Credenciais de filial necessárias' });
}

    const { data: userData } = await supabase
      .from('acessos')
      .select('nome, tipo_acesso')
      .eq('nome', user)
      .eq('senha', password)
      .single();

    if (!userData) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    if (userData.tipo_acesso !== 'ALL' && userData.tipo_acesso !== filial) {
      return res.status(403).json({ error: 'Acesso negado a esta filial' });
    }

    // Processar requisição
    let query = supabase.from(table);
    
    if (req.method === 'GET') {
      // Aplicar filtros da query string
      Object.entries(queryParams).forEach(([key, value]) => {
        if (key.includes('=eq.')) {
          const field = key.replace('=eq.', '');
          query = query.eq(field, value);
        } else if (key.includes('=gte.')) {
          const field = key.replace('=gte.', '');
          query = query.gte(field, value);
        } else if (key.includes('=lte.')) {
          const field = key.replace('=lte.', '');
          query = query.lte(field, value);
        } else if (key.includes('=in.')) {
          const field = key.replace('=in.', '');
          const values = value.replace('(', '').replace(')', '').split(',');
          query = query.in(field, values);
        } else if (key === 'select') {
          query = query.select(value);
        } else if (key === 'order') {
          const [field, direction] = value.split('.');
          query = query.order(field, { ascending: direction === 'asc' });
        } else if (key === 'limit') {
          query = query.limit(parseInt(value));
        }
      });

      if (!['filiais', 'acessos'].includes(table)) {
        query = query.eq('filial', filial);
      }
    } else if (req.method === 'POST') {
      const dataWithFilial = !['filiais', 'acessos'].includes(table) 
        ? { ...req.body, filial } 
        : req.body;
      query = query.insert(dataWithFilial).select();
    } else if (req.method === 'PATCH') {
      Object.entries(queryParams).forEach(([key, value]) => {
        if (key.includes('=eq.')) {
          const field = key.replace('=eq.', '');
          query = query.eq(field, value);
        }
      });
      if (!['filiais', 'acessos'].includes(table)) {
        query = query.eq('filial', filial);
      }
      query = query.update(req.body).select();
    } else if (req.method === 'DELETE') {
      Object.entries(queryParams).forEach(([key, value]) => {
        if (key.includes('=eq.')) {
          const field = key.replace('=eq.', '');
          query = query.eq(field, value);
        }
      });
      if (!['filiais', 'acessos'].includes(table)) {
        query = query.eq('filial', filial);
      }
      query = query.delete();
    }

    const { data, error } = await query;
    
    if (error) {
      return res.status(400).json({ error: error.message });
    }
    
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Erro interno' });
  }
}
