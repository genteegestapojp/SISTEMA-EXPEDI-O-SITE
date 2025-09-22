import { createClient } from '@supabase/supabase-js';
import jwt from 'jsonwebtoken';

// Configuração segura usando variáveis de ambiente
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const jwtSecret = process.env.JWT_SECRET;
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'];

if (!supabaseUrl || !supabaseServiceKey || !jwtSecret) {
    throw new Error('Variáveis de ambiente obrigatórias não configuradas');
}

const supabase = createClient(supabaseUrl, supabaseServiceKey);

// Cache de sessões válidas (em produção, use Redis)
const validSessions = new Map();

export default async function handler(req, res) {
    // 1. CORS Seguro
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    }
    
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Session-Token');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    try {
        // 2. Verificação de Autenticação
        const sessionToken = req.headers['x-session-token'];
        if (!sessionToken) {
            return res.status(401).json({ error: 'Token de sessão obrigatório' });
        }

        // Verificar se é um token JWT válido
        let decodedToken;
        try {
            decodedToken = jwt.verify(sessionToken, jwtSecret);
        } catch (jwtError) {
            return res.status(401).json({ error: 'Token inválido' });
        }

        // Verificar se a sessão ainda é válida
        const sessionKey = `${decodedToken.userId}_${decodedToken.filial}`;
        if (!validSessions.has(sessionKey)) {
            // Verificar no banco se o usuário ainda existe e tem permissão
            const { data: userData } = await supabase
                .from('acessos')
                .select('nome, tipo_acesso')
                .eq('nome', decodedToken.userId)
                .single();

            if (!userData) {
                return res.status(401).json({ error: 'Usuário não encontrado' });
            }

            if (userData.tipo_acesso !== 'ALL' && userData.tipo_acesso !== decodedToken.filial) {
                return res.status(403).json({ error: 'Acesso negado a esta filial' });
            }

            // Adicionar à cache de sessões válidas (expire em 1 hora)
            validSessions.set(sessionKey, {
                user: userData,
                expires: Date.now() + (60 * 60 * 1000)
            });
        }

        // Limpar sessões expiradas
        cleanExpiredSessions();

        // 3. Processar requisição
        const { table, ...queryParams } = req.query;
        
        if (!table) {
            return res.status(400).json({ error: 'Parâmetro table é obrigatório' });
        }

        // Verificar se a tabela é permitida
        const allowedTables = [
            'expeditions', 'expedition_items', 'lojas', 'docas', 'veiculos', 
            'motoristas', 'lideres', 'filiais', 'acessos', 'pontos_interesse',
            'gps_tracking', 'veiculos_status_historico'
        ];

        if (!allowedTables.includes(table)) {
            return res.status(403).json({ error: 'Tabela não permitida' });
        }

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

            // Aplicar filtro de filial para tabelas que não são globais
            if (!['filiais', 'acessos', 'gps_tracking', 'veiculos_status_historico'].includes(table)) {
                query = query.eq('filial', decodedToken.filial);
            }
        } else if (req.method === 'POST') {
            // Validar dados de entrada
            if (!req.body || typeof req.body !== 'object') {
                return res.status(400).json({ error: 'Dados inválidos' });
            }

            const dataWithFilial = !['filiais', 'acessos', 'gps_tracking', 'veiculos_status_historico'].includes(table) 
                ? { ...req.body, filial: decodedToken.filial } 
                : req.body;
            
            query = query.insert(dataWithFilial).select();
        } else if (req.method === 'PATCH') {
            // Aplicar filtros para identificar registro
            Object.entries(queryParams).forEach(([key, value]) => {
                if (key.includes('=eq.')) {
                    const field = key.replace('=eq.', '');
                    query = query.eq(field, value);
                }
            });
            
            if (!['filiais', 'acessos', 'gps_tracking', 'veiculos_status_historico'].includes(table)) {
                query = query.eq('filial', decodedToken.filial);
            }
            
            query = query.update(req.body).select();
        } else if (req.method === 'DELETE') {
            // Aplicar filtros para identificar registro
            Object.entries(queryParams).forEach(([key, value]) => {
                if (key.includes('=eq.')) {
                    const field = key.replace('=eq.', '');
                    query = query.eq(field, value);
                }
            });
            
            if (!['filiais', 'acessos', 'gps_tracking', 'veiculos_status_historico'].includes(table)) {
                query = query.eq('filial', decodedToken.filial);
            }
            
            query = query.delete();
        }

        const { data, error } = await query;
        
        if (error) {
            console.error('Supabase error:', error);
            return res.status(400).json({ error: error.message });
        }
        
        res.json(data);

    } catch (error) {
        console.error('API Error:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
}

// Função para limpar sessões expiradas
function cleanExpiredSessions() {
    const now = Date.now();
    for (const [key, session] of validSessions.entries()) {
        if (session.expires < now) {
            validSessions.delete(key);
        }
    }
}

// Endpoint para autenticação (gerar token)
export async function authenticate(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Método não permitido' });
    }

    const { user, password, filial } = req.body;

    if (!user || !password) {
        return res.status(400).json({ error: 'Usuário e senha são obrigatórios' });
    }

    try {
        // Verificar credenciais no banco
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

        // Gerar token JWT
        const token = jwt.sign(
            { 
                userId: userData.nome,
                filial: filial,
                tipoAcesso: userData.tipo_acesso,
                iat: Math.floor(Date.now() / 1000),
                exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hora
            },
            jwtSecret
        );

        // Adicionar à cache de sessões válidas
        const sessionKey = `${userData.nome}_${filial}`;
        validSessions.set(sessionKey, {
            user: userData,
            expires: Date.now() + (60 * 60 * 1000)
        });

        res.json({
            success: true,
            token: token,
            user: {
                nome: userData.nome,
                tipo_acesso: userData.tipo_acesso
            }
        });

    } catch (error) {
        console.error('Auth error:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
}
