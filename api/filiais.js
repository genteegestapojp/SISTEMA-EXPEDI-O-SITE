import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseServiceKey) {
    throw new Error('Variáveis de ambiente não configuradas');
}

const supabase = createClient(supabaseUrl, supabaseServiceKey);

export default async function handler(req, res) {
    // CORS
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'];
    const origin = req.headers.origin;
    
    if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    }
    
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Método não permitido' });
    }

    try {
        // Buscar apenas filiais ativas
        const { data: filiais, error } = await supabase
            .from('filiais')
            .select('nome, descricao, ativo')
            .eq('ativo', true)
            .order('nome');

        if (error) {
            console.error('Erro ao buscar filiais:', error);
            return res.status(500).json({ error: 'Erro ao buscar filiais' });
        }

        return res.json(filiais || []);

    } catch (error) {
        console.error('Erro no endpoint de filiais:', error);
        return res.status(500).json({ error: 'Erro interno do servidor' });
    }
}
